
#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include "mbedtls/gcm.h"
#include "web_handler.h"

#define SERVICE_UUID        "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define DIGITAL_CHAR_UUID   "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
#define AUTH_CHAR_UUID      "6e400004-b5a3-f393-e0a9-e50e24dcca9e"
#define STATUS_CHAR_UUID    "6e400005-b5a3-f393-e0a9-e50e24dcca9e"
#define HEARTBEAT_CHAR_UUID "6e400006-b5a3-f393-e0a9-e50e24dcca9e"

#define AUTH_TIMEOUT_MS  30000

#define NET_NAME_MIN_LEN 6
#define NET_NAME_MAX_LEN 10
#define WIFI_PASS_MIN_LEN 8
#define WIFI_PASS_MAX_LEN 10

#define DEFAULT_WIFI_SSID "RRC_PLC"
#define DEFAULT_WIFI_PASSWORD  "12345678"
#define DEFAULT_BLE_NAME       "RRC_PLC"

#define WIFI_RETRY_INTERVAL_MS  10000

char bleName[32]       = DEFAULT_BLE_NAME;
char wifiSsid[32]      = DEFAULT_WIFI_SSID;
char wifiPassword[64]  = DEFAULT_WIFI_PASSWORD;

User        users[MAX_USERS];
int         userCount    = 0;
Preferences prefs;
WebServer   webServer(80);

// Output pin lookup table — order must match the web UI dropdowns (index 0-4)
const OutPin OUTPUT_PINS[NUM_OUTPUT_PINS] = {
  { "R0_0", R0_0 },
  { "Q0_0", Q0_0 },
  { "Q0_1", Q0_1 },
  { "Q0_2", Q0_2 },
  { "Q0_3", Q0_3 }
};
// aes key must be 16 bytes for AES-128
static const uint8_t aesKey[16] = {
  0x54, 0x55, 0x53, 0x4B,
  0x45, 0x52, 0x5F, 0x52,
  0x52, 0x43, 0x5F, 0x44,
  0x45, 0x56, 0x5F, 0x31
};

// AES-GCM decryption helper — accepts either hex text or raw bytes
static bool decryptAESGCM_from_bytes(const uint8_t *encrypted, size_t encryptedLen, uint8_t *decrypted, size_t *decryptedLen) {
  if (encryptedLen < 12 + 16) return false; // need IV(12) + TAG(16)

  const uint8_t *iv = encrypted; // first 12 bytes
  const uint8_t *tag = encrypted + encryptedLen - 16; // last 16 bytes
  const uint8_t *cipher = encrypted + 12;
  size_t cipherLen = encryptedLen - 12 - 16;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128) != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  int res = mbedtls_gcm_auth_decrypt(
    &gcm,
    cipherLen,
    iv, 12,
    NULL, 0,
    tag, 16,
    cipher,
    decrypted
  );

  mbedtls_gcm_free(&gcm);

  if (res != 0) return false;
  *decryptedLen = cipherLen;
  return true;
}

// forward declare helpers defined later
static bool decodeHexText(const std::string& text, uint8_t *output, size_t outputSize, size_t *outputLen);
static uint64_t read48be(const uint8_t *buf);
static bool isCounterFresh(uint64_t sessionId, uint64_t counter);
static void updateLastCounter(uint64_t sessionId, uint64_t counter);

static bool decodePayload(const std::string &data, uint8_t *output, size_t outputSize, size_t *outputLen) {
  if (decodeHexText(data, output, outputSize, outputLen)) {
    return true;
  }

  std::string hexed;
  hexed.reserve(data.size() * 2);
  const char hexDigits[] = "0123456789ABCDEF";
  for (unsigned char c : data) {
    hexed.push_back(hexDigits[(c >> 4) & 0xF]);
    hexed.push_back(hexDigits[c & 0xF]);
  }

  if (decodeHexText(hexed, output, outputSize, outputLen)) {
    return true;
  }

  if (data.size() > outputSize) return false;
  memcpy(output, data.data(), data.size());
  *outputLen = data.size();
  return true;
}

struct SessionCounterEntry {
  uint64_t sessionId;
  uint64_t lastCounter;
  bool used;
};

static const int MAX_SESSION_COUNTER_ENTRIES = 8;
static SessionCounterEntry sessionCounters[MAX_SESSION_COUNTER_ENTRIES] = {};

static uint64_t read48be(const uint8_t *buf) {
  return ((uint64_t)buf[0] << 40) | ((uint64_t)buf[1] << 32) |
         ((uint64_t)buf[2] << 24) | ((uint64_t)buf[3] << 16) |
         ((uint64_t)buf[4] << 8)  | (uint64_t)buf[5];
}

static bool isCounterFresh(uint64_t sessionId, uint64_t counter) {
  for (int i = 0; i < MAX_SESSION_COUNTER_ENTRIES; ++i) {
    if (sessionCounters[i].used && sessionCounters[i].sessionId == sessionId) {
      return counter > sessionCounters[i].lastCounter;
    }
  }
  return true;
}

static void updateLastCounter(uint64_t sessionId, uint64_t counter) {
  int freeIndex = -1;
  int replaceIndex = 0;
  uint64_t oldestCounter = UINT64_MAX;

  for (int i = 0; i < MAX_SESSION_COUNTER_ENTRIES; ++i) {
    if (!sessionCounters[i].used) {
      freeIndex = i;
      break;
    }
    if (sessionCounters[i].sessionId == sessionId) {
      sessionCounters[i].lastCounter = counter;
      return;
    }
    if (sessionCounters[i].lastCounter < oldestCounter) {
      oldestCounter = sessionCounters[i].lastCounter;
      replaceIndex = i;
    }
  }

  int target = (freeIndex >= 0) ? freeIndex : replaceIndex;
  sessionCounters[target].used = true;
  sessionCounters[target].sessionId = sessionId;
  sessionCounters[target].lastCounter = counter;
}

static bool decryptAndValidateEncryptedPayload(const std::string &value, uint8_t *decrypted, size_t *decryptedLen, uint64_t &sessionId, uint64_t &counter) {
  uint8_t encrypted[256];
  size_t encryptedLen = 0;

  if (!decodePayload(value, encrypted, sizeof(encrypted), &encryptedLen)) {
    return false;
  }

  if (encryptedLen < 12 + 16) {
    return false;
  }

  sessionId = read48be(encrypted);
  counter   = read48be(encrypted + 6);

  if (!isCounterFresh(sessionId, counter)) {
    return false;
  }

  if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, decryptedLen)) {
    return false;
  }

  updateLastCounter(sessionId, counter);
  return true;
}

static bool decryptAESGCM_hex_or_raw(const std::string &data, uint8_t *decrypted, size_t *decryptedLen) {
  uint8_t buf[256];
  size_t bufLen = 0;

  if (!decodePayload(data, buf, sizeof(buf), &bufLen)) {
    return false;
  }

  if (bufLen >= 12 + 16) {
    Serial.print("Detected HEX payload — IV=");
    for (size_t i = 0; i < 12; ++i) Serial.printf("%02X", buf[i]);
    Serial.print(" CIPHER=");
    size_t cipherEnd = bufLen - 16;
    for (size_t i = 12; i < cipherEnd; ++i) Serial.printf("%02X", buf[i]);
    Serial.print(" TAG=");
    for (size_t i = cipherEnd; i < bufLen; ++i) Serial.printf("%02X", buf[i]);
    Serial.println();
  }

  return decryptAESGCM_from_bytes(buf, bufLen, decrypted, decryptedLen);
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool decodeHexText(const std::string& text, uint8_t *output, size_t outputSize, size_t *outputLen) {
  int highNibble = -1;
  size_t len = 0;
  bool sawHex = false;

  for (char c : text) {
    if (c == ' ' || c == ':' || c == '-' || c == '\r' || c == '\n' || c == '\t') {
      continue;
    }

    int nibble = hexNibble(c);
    if (nibble < 0) {
      return false;
    }

    sawHex = true;
    if (highNibble < 0) {
      highNibble = nibble;
    } else {
      if (len >= outputSize) {
        return false;
      }
      output[len++] = (uint8_t)((highNibble << 4) | nibble);
      highNibble = -1;
    }
  }

  if (!sawHex || highNibble >= 0) {
    return false;
  }

  *outputLen = len;
  return true;
}

static void logBLEReceivedData(const char *label, const std::string &data) {
  Serial.printf("%s: length=%u\n", label, (unsigned)data.length());
  if (data.empty()) return;

  Serial.print("  RAW HEX: ");
  for (unsigned char c : data) {
    Serial.printf("%02X", c);
  }
  Serial.println();

  Serial.print("  RAW ASCII: ");
  for (unsigned char c : data) {
    if (isprint(c)) {
      Serial.write(c);
    } else {
      Serial.print('.');
    }
  }
  Serial.println();
}

// Current output-to-motion mapping (indices into OUTPUT_PINS[])
// Defaults match the legacy hardcoded assignments
uint8_t outIdxEstop = 0;  // R0_0
uint8_t outIdxUp    = 1;  // Q0_0
uint8_t outIdxDown  = 2;  // Q0_1
uint8_t outIdxLeft  = 3;  // Q0_2
uint8_t outIdxRight = 4;  // Q0_3

// Write to a configured output only when a real pin is assigned.
// outIdxXxx == NUM_OUTPUT_PINS means "None" — skip the write.
#define DOUT(idx, val) \
  do { if ((idx) < NUM_OUTPUT_PINS) digitalWrite(OUTPUT_PINS[(idx)].pin, (val)); } while(0)

static void forceAllOutputsOff() {
  motionEstop = true;   // emergency mode: E-STOP output LOW
  motionUp    = false;
  motionDown  = false;
  motionLeft  = false;
  motionRight = false;
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    digitalWrite(OUTPUT_PINS[i].pin, LOW);
  }
}

bool motionEstop = true;
bool motionUp    = false;
bool motionDown  = false;
bool motionLeft  = false;
bool motionRight = false;

bool          wifiConnected  = false;
unsigned long wifiRetryTime  = 0;

// BLE
BLEServer         *pBLEServer    = nullptr;
BLECharacteristic *digitalChar   = nullptr;
BLECharacteristic *authChar      = nullptr;
BLECharacteristic *statusChar    = nullptr;
BLECharacteristic *heartbeatChar = nullptr;

bool     deviceConnected  = false;
bool     authenticated    = false;
char     connectedUserEmail[64] = "";
uint16_t connId           = 0;        
unsigned long connectTime = 0;

bool          heartbeatAlive     = false;
unsigned long lastHeartbeatTime  = 0;
int           heartbeatMissCount = 0;


void saveUsers() {
  prefs.begin("bleusers", false);
  prefs.putInt("count", userCount);
  for (int i = 0; i < userCount; i++) {
    char ekey[12], pkey[12], nkey[12], rkey[12];
    sprintf(ekey, "email_%d", i);
    sprintf(pkey, "pass_%d",  i);
    sprintf(nkey, "name_%d",  i);
    sprintf(rkey, "role_%d",  i);
    prefs.putString(ekey, users[i].email);
    prefs.putString(pkey, users[i].password);
    prefs.putString(nkey, users[i].name);
    prefs.putString(rkey, users[i].role);
  }
  prefs.end();
}

void loadUsers() {
  prefs.begin("bleusers", true);
  userCount = prefs.getInt("count", 0);
  for (int i = 0; i < userCount && i < MAX_USERS; i++) {
    char ekey[12], pkey[12], nkey[12], rkey[12];
    sprintf(ekey, "email_%d", i);
    sprintf(pkey, "pass_%d",  i);
    sprintf(nkey, "name_%d",  i);
    sprintf(rkey, "role_%d",  i);
    prefs.getString(ekey, users[i].email,    sizeof(users[i].email));
    prefs.getString(pkey, users[i].password, sizeof(users[i].password));
    prefs.getString(nkey, users[i].name,     sizeof(users[i].name));
    prefs.getString(rkey, users[i].role,     sizeof(users[i].role));
    // backward compat: if name/role empty, fill defaults
    if (users[i].name[0] == '\0') strncpy(users[i].name, users[i].email, sizeof(users[i].name));
    if (users[i].role[0] == '\0') strncpy(users[i].role, "Operator",     sizeof(users[i].role));
  }
  prefs.end();

  // Always ensure at least one Admin user exists in the list.
  // Handles both fresh NVS (userCount==0) and stale NVS from older firmware
  // that did not include the admin@plc.com account.
  bool hasAdmin = false;
  for (int i = 0; i < userCount; i++) {
    if (String(users[i].role) == "Admin") { hasAdmin = true; break; }
  }
  if (!hasAdmin && userCount < MAX_USERS) {
    strncpy(users[userCount].name,     "Admin",         sizeof(users[0].name));
    strncpy(users[userCount].email,    "admin@plc.com", sizeof(users[0].email));
    strncpy(users[userCount].password, "Admin123",      sizeof(users[0].password));
    strncpy(users[userCount].role,     "Admin",         sizeof(users[0].role));
    userCount++;
    saveUsers();
    Serial.println("Default admin user created/restored (admin@plc.com / Admin123)");
  }
}

// Sets all 5 output GPIOs to OUTPUT mode.
// Default runtime state keeps E-STOP output ON (unless emergency is active).
// Called on startup and whenever the configuration is changed.
void applyOutputConfig() {
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    digitalWrite(OUTPUT_PINS[i].pin, LOW);
  }
  DOUT(outIdxEstop, motionEstop ? LOW : HIGH);
}

// Reads output-to-motion pin indices from NVS namespace "outconfig".
// Falls back to the legacy defaults if the key is missing or out of range.
void loadOutputConfig() {
  prefs.begin("outconfig", true);
  int e = prefs.getInt("estop_idx", 0);
  int u = prefs.getInt("up_idx",    1);
  int d = prefs.getInt("down_idx",  2);
  int l = prefs.getInt("left_idx",  3);
  int r = prefs.getInt("right_idx", 4);
  prefs.end();

  // Allow 0..NUM_OUTPUT_PINS (NUM_OUTPUT_PINS = "None" / unassigned)
  outIdxEstop = (e >= 0 && e <= NUM_OUTPUT_PINS) ? (uint8_t)e : 0;
  outIdxUp    = (u >= 0 && u <= NUM_OUTPUT_PINS) ? (uint8_t)u : 1;
  outIdxDown  = (d >= 0 && d <= NUM_OUTPUT_PINS) ? (uint8_t)d : 2;
  outIdxLeft  = (l >= 0 && l <= NUM_OUTPUT_PINS) ? (uint8_t)l : 3;
  outIdxRight = (r >= 0 && r <= NUM_OUTPUT_PINS) ? (uint8_t)r : 4;
  applyOutputConfig();
  auto pl = [](uint8_t i) -> const char* {
    return (i < NUM_OUTPUT_PINS) ? OUTPUT_PINS[i].label : "None";
  };
  Serial.printf("Output config: ESTOP=%s UP=%s DOWN=%s LEFT=%s RIGHT=%s\n",
    pl(outIdxEstop), pl(outIdxUp), pl(outIdxDown), pl(outIdxLeft), pl(outIdxRight));
}

// Persists the current indices to NVS and re-initialises pin modes.
void saveOutputConfig() {
  prefs.begin("outconfig", false);
  prefs.putInt("estop_idx", outIdxEstop);
  prefs.putInt("up_idx",    outIdxUp);
  prefs.putInt("down_idx",  outIdxDown);
  prefs.putInt("left_idx",  outIdxLeft);
  prefs.putInt("right_idx", outIdxRight);
  prefs.end();
  applyOutputConfig();
}

// Reads BLE and WiFi credentials from NVS and applies defaults if missing.
void loadNetworkConfig() {
  prefs.begin("netconfig", true);
  String ssid = prefs.getString("wifi_ssid", DEFAULT_WIFI_SSID);
  String pwd  = prefs.getString("wifi_password", DEFAULT_WIFI_PASSWORD);
  String ble  = prefs.getString("ble_name", DEFAULT_BLE_NAME);
  prefs.end();

  if (ssid.length() < NET_NAME_MIN_LEN || ssid.length() > NET_NAME_MAX_LEN) ssid = DEFAULT_WIFI_SSID;
  if (pwd.length() < WIFI_PASS_MIN_LEN || pwd.length() > WIFI_PASS_MAX_LEN) pwd = DEFAULT_WIFI_PASSWORD;
  if (ble.length() < NET_NAME_MIN_LEN || ble.length() > NET_NAME_MAX_LEN || !ble.startsWith("RRC_")) ble = DEFAULT_BLE_NAME;

  if (ssid.length() >= sizeof(wifiSsid)) ssid = ssid.substring(0, sizeof(wifiSsid) - 1);
  if (pwd.length() >= sizeof(wifiPassword)) pwd = pwd.substring(0, sizeof(wifiPassword) - 1);
  if (ble.length() >= sizeof(bleName)) ble = ble.substring(0, sizeof(bleName) - 1);

  ssid.toCharArray(wifiSsid, sizeof(wifiSsid));
  pwd.toCharArray(wifiPassword, sizeof(wifiPassword));
  ble.toCharArray(bleName, sizeof(bleName));
}

void saveNetworkConfig() {
  prefs.begin("netconfig", false);
  prefs.putString("wifi_ssid", wifiSsid);
  prefs.putString("wifi_password", wifiPassword);
  prefs.putString("ble_name", bleName);
  prefs.end();
}

// Sends current motion state to the mobile app via the status characteristic.
// Format: "ST:[estop],[up],[down]"  e.g. "0,1,0" = UP active
void notifyMotionStatus() {
  if (!deviceConnected || !authenticated || !statusChar) return;
  char buf[24];
  snprintf(buf, sizeof(buf), "%d,%d,%d,%d,%d",
    motionEstop ? 1 : 0,
    motionUp    ? 1 : 0,
    motionDown  ? 1 : 0,
    motionLeft  ? 1 : 0,
    motionRight ? 1 : 0);
  statusChar->setValue(buf);
  statusChar->notify();
  Serial.printf("BLE status notify: %s\n", buf);
}

static bool isHeartbeatHealthy() {
  if (!deviceConnected || !authenticated || lastHeartbeatTime == 0) return false;
  return (millis() - lastHeartbeatTime) <= 500;
}

static void updateOutputPinsFromState() {
  if (!deviceConnected || !authenticated || !isHeartbeatHealthy()) {
    for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
      digitalWrite(OUTPUT_PINS[i].pin, LOW);
    }
    return;
  }

  if (motionEstop) {
    for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
      digitalWrite(OUTPUT_PINS[i].pin, LOW);
    }
    return;
  }

  DOUT(outIdxEstop, HIGH);
  DOUT(outIdxUp,    motionUp    ? HIGH : LOW);
  DOUT(outIdxDown,  motionDown  ? HIGH : LOW);
  DOUT(outIdxLeft,  motionLeft  ? HIGH : LOW);
  DOUT(outIdxRight, motionRight ? HIGH : LOW);
}

bool checkCredentials(const std::string& email, const std::string& password) {
  for (int i = 0; i < userCount; i++) {
    if (email == users[i].email && password == users[i].password) {
      return true;
    }
  }
  return false;
}

void startWiFi() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP(wifiSsid, wifiPassword);
  delay(100); // allow AP to start
  Serial.println("WiFi AP started");
  Serial.println("SSID: " + String(wifiSsid));
  Serial.println("Password: " + String(wifiPassword));
  Serial.println("Web panel: http://" + WiFi.softAPIP().toString() + "/");
}

void handleWiFi() {
  // No connection management needed in AP mode
}

// ---------------- SERVER CALLBACK ----------------
class MyServerCallbacks : public BLEServerCallbacks {
  // Extended onConnect gives us the connection handle
  void onConnect(BLEServer* pServer, esp_ble_gatts_cb_param_t *param) {
    deviceConnected = true;
    authenticated   = false;
    connId          = param->connect.conn_id;
    connectTime     = millis();
    Serial.println("Mobile connected — waiting for credentials");

    forceAllOutputsOff();
    Serial.println("Outputs forced OFF until authentication");

    authChar->setValue("AUTH_REQ:email|password");
    authChar->notify();
  }

  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    authenticated   = false;
    connectedUserEmail[0] = '\0';
    Serial.println("Mobile disconnected");

    forceAllOutputsOff();
    Serial.println("All outputs forced OFF due to disconnect");

    delay(100);
    BLEDevice::startAdvertising();
  }
};

class AuthCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    std::string data = pCharacteristic->getValue();
    logBLEReceivedData("AUTH write received", data);
    if (data.length() < 3) {
      authChar->setValue("AUTH_FAIL");
      authChar->notify();
      delay(200);
      pBLEServer->disconnect(connId);
      return;
    }

    // Split on '|'
    size_t sep = data.find('|');
    if (sep == std::string::npos) {
      Serial.println("Auth: bad format — expected email|password");
      authChar->setValue("AUTH_FAIL");
      authChar->notify();
      delay(200);
      pBLEServer->disconnect(connId);
      return;
    }

    std::string email    = data.substr(0, sep);
    std::string password = data.substr(sep + 1);

    Serial.printf("Auth attempt — email: %s\n", email.c_str());

    if (checkCredentials(email, password)) {
      authenticated = true;
      strncpy(connectedUserEmail, email.c_str(), sizeof(connectedUserEmail) - 1);
      connectedUserEmail[sizeof(connectedUserEmail) - 1] = '\0';
      authChar->setValue("AUTH_OK");
      authChar->notify();
      Serial.printf("Authentication SUCCESS — user: %s\n", email.c_str());
    } else {
      authenticated = false;
      authChar->setValue("AUTH_FAIL");
      authChar->notify();
      Serial.printf("Authentication FAILED — user: %s\n", email.c_str());
      delay(200);  // allow notify to reach the app before disconnect
      pBLEServer->disconnect(connId);
    }
  }
};

// ---------------- DIGITAL WRITE CALLBACK ----------------
// Expected data format: AES-GCM encrypted payload encoded as hex text or raw bytes.
// Format (bytes): IV(12) | CIPHER | TAG(16)
// The decrypted payload must be a comma-separated motion command list:
//   [estop,up,down,left,right]
// e.g. "[0,1,0,0,0]" or "0,1,0,0,0"
// estop=1 → E-STOP output OFF and ALL outputs OFF (emergency stop)
// estop=0 → E-STOP output ON and up/down/left/right follow command values
class DigitalCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    // Reject commands from unauthenticated clients
    if (!authenticated) {
      Serial.println("Command rejected — not authenticated");
      return;
    }

    std::string value = pCharacteristic->getValue();
    logBLEReceivedData("DIGITAL write received", value);
    if (value.length() < 1) return;

    uint8_t encrypted[256];
    size_t encryptedLen = 0;
    if (!decodePayload(value, encrypted, sizeof(encrypted), &encryptedLen)) {
      Serial.println("Command rejected — unable to decode encrypted payload");
      return;
    }

    if (encryptedLen < 12 + 16) {
      Serial.println("Command rejected — encrypted payload too short");
      return;
    }

    uint64_t sessionId = read48be(encrypted);
    uint64_t counter   = read48be(encrypted + 6);
    if (!isCounterFresh(sessionId, counter)) {
      Serial.printf("Command rejected — counter not incremented (session=%012llX counter=%llu)\n", (unsigned long long)sessionId, (unsigned long long)counter);
      return;
    }

    // Decrypt using AES-GCM (accepts hex text or raw bytes: IV(12) | CIPHER | TAG(16))
    uint8_t decrypted[128];
    size_t decryptedLen = 0;
    if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, &decryptedLen)) {
      Serial.println("DECRYPT FAILED");
      return;
    }

    updateLastCounter(sessionId, counter);

    // Trim trailing nulls if any
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;

    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    Serial.printf("Encrypted data length: %u\n", (unsigned)value.length());
    Serial.print("Decrypted bytes (hex): ");
    for (size_t i = 0; i < decryptedLen; ++i) {
      Serial.printf("%02X", decrypted[i]);
    }
    Serial.println();
    Serial.print("Decrypted ASCII: ");
    Serial.println(reinterpret_cast<char*>(decrypted));

    // Parse CSV payload like: "1,0,1,0,0" (estop,up,down,left,right)
    std::string s = reinterpret_cast<char*>(decrypted);
    // Trim leading/trailing whitespace
    auto trim = [](std::string &str) {
      while (!str.empty() && isspace((unsigned char)str.front())) str.erase(str.begin());
      while (!str.empty() && isspace((unsigned char)str.back())) str.pop_back();
    };
    trim(s);
    // Remove surrounding brackets if present
    if (!s.empty() && s.front() == '[' && s.back() == ']') {
      s = s.substr(1, s.size() - 2);
      trim(s);
    }

    int vals[5] = {0,0,0,0,0};
    size_t idx = 0;
    size_t start = 0;
    while (start < s.size() && idx < 5) {
      size_t pos = s.find(',', start);
      std::string token = (pos == std::string::npos) ? s.substr(start) : s.substr(start, pos - start);
      trim(token);
      if (!token.empty()) {
        vals[idx] = atoi(token.c_str());
      } else {
        vals[idx] = 0;
      }
      idx++;
      if (pos == std::string::npos) break;
      start = pos + 1;
    }

    int estop = vals[0];
    int up    = vals[1];
    int down  = vals[2];
    int left  = vals[3];
    int right = vals[4];

    Serial.printf("Received CSV: [%d,%d,%d,%d,%d]\n", estop, up, down, left, right);

    // Safety: UP/DOWN and LEFT/RIGHT pairs must never both be active at the same time
    if (up && down) {
      up = 0; down = 0;
      Serial.println("CONFLICT: UP+DOWN both active — both forced OFF");
    }
    if (left && right) {
      left = 0; right = 0;
      Serial.println("CONFLICT: LEFT+RIGHT both active — both forced OFF");
    }

    if (estop == 1) {
      // Emergency stop — all outputs OFF (including E-STOP output)
      motionEstop = true;
      motionUp    = false;
      motionDown  = false;
      motionLeft  = false;
      motionRight = false;
      Serial.println("E-STOP ACTIVE: E-STOP/Others OFF");
    } else {
      // Normal operation: estop==0 enables outputs
      motionEstop = false;
      motionUp    = (up != 0);
      motionDown  = (down != 0);
      motionLeft  = (left != 0);
      motionRight = (right != 0);
      Serial.printf("E-STOP:OFF UP:%d DOWN:%d LEFT:%d RIGHT:%d\n", motionUp, motionDown, motionLeft, motionRight);
    }

    updateOutputPinsFromState();
    notifyMotionStatus();
  }
};

class HeartbeatCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    if (!authenticated) {
      Serial.println("Heartbeat ignored — not authenticated");
      return;
    }

    std::string data = pCharacteristic->getValue();
    if (data.length() == 0) {
      Serial.println("Heartbeat characteristic received EMPTY data");
      return;
    }

    uint8_t decrypted[32];
    size_t decryptedLen = 0;
    uint64_t sessionId = 0;
    uint64_t counter = 0;

    if (!decryptAndValidateEncryptedPayload(data, decrypted, &decryptedLen, sessionId, counter)) {
      return;
    }

    // Trim trailing nulls if any
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;
    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    if (strcmp(reinterpret_cast<char*>(decrypted), "HB") != 0) {
      return;
    }

    lastHeartbeatTime = millis();
    heartbeatMissCount = 0;
    if (!heartbeatAlive) {
      heartbeatAlive = true;
    }
    updateOutputPinsFromState();
  }
};

void setup() {
  Serial.begin(115200);

  loadUsers();
  loadOutputConfig();  // reads NVS, applies pinMode + LOW for all 5 outputs
  // Explicitly configure digital outputs and 24V supply pins
  pinMode(Q0_0, OUTPUT);
  pinMode(Q0_1, OUTPUT);
  pinMode(Q0_2, OUTPUT);
  pinMode(Q0_3, OUTPUT);

 pinMode(S0_24v, OUTPUT);
 pinMode(S1_24v, OUTPUT);
 pinMode(S2_24v, OUTPUT);
 pinMode(S3_24v, OUTPUT);

 digitalWrite(S0_24v, HIGH);
 digitalWrite(S1_24v, HIGH);
 digitalWrite(S2_24v, HIGH);
 digitalWrite(S3_24v, HIGH);

  // Ensure all configured output pins are set to OUTPUT on startup
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    digitalWrite(OUTPUT_PINS[i].pin, LOW);
  }
  loadNetworkConfig();
  forceAllOutputsOff();

  startWiFi();

  setupWebRoutes();

  BLEDevice::init(bleName);

  pBLEServer = BLEDevice::createServer();
  pBLEServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pBLEServer->createService(SERVICE_UUID);

  
  digitalChar = pService->createCharacteristic(
    DIGITAL_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  digitalChar->setCallbacks(new DigitalCallbacks());

  authChar = pService->createCharacteristic(
    AUTH_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_NOTIFY
  );
  authChar->addDescriptor(new BLE2902());
  authChar->setCallbacks(new AuthCallbacks());

  statusChar = pService->createCharacteristic(
    STATUS_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  statusChar->addDescriptor(new BLE2902());

  heartbeatChar = pService->createCharacteristic(
    HEARTBEAT_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  heartbeatChar->setCallbacks(new HeartbeatCallbacks());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->start();

  Serial.println("BLE Ready...");
}

void loop() {

  if (deviceConnected) {

    if (!authenticated && (millis() - connectTime > AUTH_TIMEOUT_MS)) {
      Serial.println("Auth timeout — disconnecting client");
      authChar->setValue("AUTH_TIMEOUT");
      authChar->notify();
      delay(200);
      pBLEServer->disconnect(connId);
      return;
    }

    unsigned long elapsed = lastHeartbeatTime == 0 ? ULONG_MAX : (millis() - lastHeartbeatTime);
    int newMissCount = 0;
    
    if (elapsed > 100) newMissCount = 1;
    if (elapsed > 200) newMissCount = 2;
    if (elapsed > 300) newMissCount = 3;
    if (elapsed > 400) newMissCount = 4;
    if (elapsed > 500) newMissCount = 5;

    if (newMissCount != heartbeatMissCount) {
      heartbeatMissCount = newMissCount;
      if (heartbeatMissCount == 1) {
        Serial.println("✗ Heartbeat NOT received — missing for > 100ms");
      } else if (heartbeatMissCount == 2) {
        Serial.println("✗ Heartbeat NOT received — missing for > 200ms");
      } else if (heartbeatMissCount == 3) {
        Serial.println("✗ Heartbeat NOT received — missing for > 300ms");
      } else if (heartbeatMissCount == 4) {
        Serial.println("✗ Heartbeat NOT received — missing for > 400ms");
      } else if (heartbeatMissCount >= 5) {
        if (heartbeatAlive) {
          heartbeatAlive = false;
          Serial.println("✗ Heartbeat NOT received — missing counter reached 5 (500ms) — outputs turned OFF");
        } else if (lastHeartbeatTime == 0) {
          Serial.println("✗ Heartbeat NOT received — no data ever arrived on heartbeat characteristic");
        }
      }
    }

    updateOutputPinsFromState();
  } else {
    heartbeatAlive = false;
    forceAllOutputsOff();
  }

  handleWiFi(); // does nothing in AP mode
  webServer.handleClient();

  delay(20);
}
