
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

#define AUTH_TIMEOUT_MS  60000

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

// Logical output functions for the 5 outputs
const char* OUTPUT_FUNCTIONS[NUM_OUTPUT_PINS] = {
  "DF1",
  "DF2",
  "DF3",
  "DF4",
  "DF5"
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

// Global IV counter for encrypting replies (12 bytes)
static uint8_t replyIvCounter[12] = {0};

static void incrementReplyIv() {
  for (int i = 11; i >= 0; --i) {
    replyIvCounter[i]++;
    if (replyIvCounter[i] != 0) break;
  }
}

static std::string bytesToHex(const uint8_t *data, size_t len) {
  static const char hexDigits[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(hexDigits[(data[i] >> 4) & 0xF]);
    out.push_back(hexDigits[data[i] & 0xF]);
  }
  return out;
}

// Encrypt plaintext into IV(12)|CIPHER|TAG(16) hex string (IV is replyIvCounter, incremented)
static bool encryptAESGCM_packet(const std::string &plain, std::string &outHex) {
  size_t len = plain.size();
  if (len > 200) return false;

  uint8_t ciphertext[256];
  uint8_t tag[16];

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128) != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }

  incrementReplyIv();

  int res = mbedtls_gcm_crypt_and_tag(
    &gcm,
    MBEDTLS_GCM_ENCRYPT,
    len,
    replyIvCounter, 12,
    NULL, 0,
    (const uint8_t*)plain.data(),
    ciphertext,
    16,
    tag
  );

  mbedtls_gcm_free(&gcm);
  if (res != 0) return false;

  // Build final hex: IV + ciphertext + tag
  outHex.clear();
  outHex += bytesToHex(replyIvCounter, 12);
  outHex += bytesToHex(ciphertext, len);
  outHex += bytesToHex(tag, 16);
  return true;
}

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

  // Serial.print("  RAW ASCII: ");
  // for (unsigned char c : data) {
  //   if (isprint(c)) {
  //     Serial.write(c);
  //   } else {
  //     Serial.print('.');
  //   }
  // }
  // Serial.println();
}

// Pin configuration: for each output pin, which digital function and motion it controls
// Defaults match the legacy hardcoded assignments: pin 0 → DF1/ESTOP, pin 1 → DF2/UP, pin 2 → DF3/DOWN, pin 3 → DF4/LEFT, pin 4 → DF5/RIGHT
PinMotion pinMotionConfig[NUM_OUTPUT_PINS] = {
  { 0, MOTION_ESTOP },
  { 1, MOTION_UP    },
  { 2, MOTION_DOWN  },
  { 3, MOTION_LEFT  },
  { 4, MOTION_RIGHT }
};

// Helper to get motion label from motion ID
const char* getMotionLabel(uint8_t motionId) {
  switch (motionId) {
    case MOTION_ESTOP:  return "&#9888; E-STOP";
    case MOTION_UP:     return "&#9650; UP";
    case MOTION_DOWN:   return "&#9660; DOWN";
    case MOTION_LEFT:   return "&#9664; LEFT";
    case MOTION_RIGHT:  return "&#9654; RIGHT";
    default:            return "&#8212; None &#8212;";
  }
}

// Helper to get motion ID from label (for parsing)
uint8_t getMotionIdForLabel(const char* label) {
  if (!label) return MOTION_NONE;
  if (strcmp(label, "estop") == 0)  return MOTION_ESTOP;
  if (strcmp(label, "up") == 0)     return MOTION_UP;
  if (strcmp(label, "down") == 0)   return MOTION_DOWN;
  if (strcmp(label, "left") == 0)   return MOTION_LEFT;
  if (strcmp(label, "right") == 0)  return MOTION_RIGHT;
  return MOTION_NONE;
}

// Write output based on current motion states and pin-motion configuration
// E-STOP is inverted: LOW = active (emergency), HIGH = inactive (normal)
// Other motions are normal: HIGH = active, LOW = inactive
#define DOUT(pinIdx, val) \
  do { if ((pinIdx) < NUM_OUTPUT_PINS) digitalWrite(OUTPUT_PINS[(pinIdx)].pin, (val)); } while(0)

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

// Sets all 5 output GPIOs to OUTPUT mode and updates their states based on current motion states.
// Called on startup and whenever the configuration is changed.
void applyOutputConfig() {
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    uint8_t motion = pinMotionConfig[i].motion;
    bool active = false;
    
    // Determine if this pin's assigned motion is currently active
    switch (motion) {
      case MOTION_ESTOP:
        active = motionEstop;
        break;
      case MOTION_UP:
        active = motionUp;
        break;
      case MOTION_DOWN:
        active = motionDown;
        break;
      case MOTION_LEFT:
        active = motionLeft;
        break;
      case MOTION_RIGHT:
        active = motionRight;
        break;
      case MOTION_NONE:
      default:
        active = false;
        break;
    }
    
    int outputValue;
    if (motion == MOTION_ESTOP) {
      outputValue = active ? LOW : HIGH;
    } else if (motion != MOTION_NONE) {
      outputValue = active ? HIGH : LOW;
    } else {
      outputValue = LOW;  // No motion assigned, keep low
    }

    DOUT(i, outputValue);
  }
}

// Reads pin configuration from NVS namespace "outconfig".
// Falls back to defaults if keys are missing or out of range.
void loadOutputConfig() {
  prefs.begin("outconfig", true);
  
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    char key[16];
    sprintf(key, "pin_%d_function", i);
    int functionId = prefs.getInt(key, -1);
    if (functionId < 0 || functionId >= NUM_OUTPUT_PINS) {
      functionId = i; // default to DF1..DF5 for each pin
    }

    sprintf(key, "func_%d_motion", i);
    int motion = prefs.getInt(key, -1);
    if (motion == -1) {
      sprintf(key, "pin_%d_motion", i);
      motion = prefs.getInt(key, i + 1);
    }

    // Clamp function and motion to valid range
    if (functionId < 0 || functionId >= NUM_OUTPUT_PINS) {
      functionId = i;
    }
    if (motion < MOTION_NONE || motion > MOTION_RIGHT) {
      motion = (i < NUM_OUTPUT_PINS) ? (i + 1) : MOTION_NONE;
    }

    pinMotionConfig[i].function = (uint8_t)functionId;
    pinMotionConfig[i].motion   = (uint8_t)motion;
  }
  
  prefs.end();
  applyOutputConfig();
  
  // Log the loaded configuration
  Serial.println("Output config loaded:");
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[i].function], OUTPUT_PINS[i].label, getMotionLabel(pinMotionConfig[i].motion));
  }
}

// Persists the current pin configuration to NVS and re-initializes pin modes.
void saveOutputConfig() {
  prefs.begin("outconfig", false);
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    char key[16];
    sprintf(key, "pin_%d_function", i);
    prefs.putInt(key, pinMotionConfig[i].function);
    sprintf(key, "pin_%d_motion", i);
    prefs.putInt(key, pinMotionConfig[i].motion);
  }
  prefs.end();
  applyOutputConfig();
  
  // Log the saved configuration
  Serial.println("Output config saved:");
  for (int i = 0; i < NUM_OUTPUT_PINS; i++) {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[i].function], OUTPUT_PINS[i].label, getMotionLabel(pinMotionConfig[i].motion));
  }
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

  // Update each pin based on its assigned motion and current motion state
  for (int p = 0; p < NUM_OUTPUT_PINS; p++) {
    uint8_t motion = pinMotionConfig[p].motion;
    bool isActive = false;
    
    switch (motion) {
      case MOTION_ESTOP:
        // E-STOP pin is HIGH in normal operation (inactive/safe state)
        // Goes LOW only when motionEstop is true (handled by guard clause above)
        isActive = false;
        break;
      case MOTION_UP:
        isActive = motionUp;
        break;
      case MOTION_DOWN:
        isActive = motionDown;
        break;
      case MOTION_LEFT:
        isActive = motionLeft;
        break;
      case MOTION_RIGHT:
        isActive = motionRight;
        break;
      case MOTION_NONE:
      default:
        isActive = false;
        break;
    }
    
    // Write to pin: E-STOP is inverted (HIGH=safe/inactive), others normal (HIGH=active)
    if (motion == MOTION_ESTOP) {
      DOUT(p, HIGH);  // E-STOP always HIGH in normal operation
    } else {
      DOUT(p, isActive ? HIGH : LOW);  // Other motions: HIGH when active
    }
  }
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

    authChar->setValue("AUTH_REQ:email|password|deviceid");
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
    // Accept encrypted auth payload: IV(12) | CIPHER | TAG(16) encoded as hex or raw
    std::string data = pCharacteristic->getValue();
    Serial.print("////Received AUTH write: ");
    Serial.println(data.c_str());
    logBLEReceivedData("AUTH write received", data);

    if (data.length() < 1) {
      Serial.println("Auth: empty payload");
      return;
    }

    // Decode encrypted packet
    uint8_t encrypted[512];
    size_t encryptedLen = 0;
    if (!decodePayload(data, encrypted, sizeof(encrypted), &encryptedLen)) {
      Serial.println("Auth: payload decode failed");
      // Reply encrypted FAIL
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
        Serial.println("Auth: sent AUTH_FAIL (encrypted)");
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    Serial.printf("Auth: decoded encrypted length=%u\n", (unsigned)encryptedLen);

    if (encryptedLen < 12 + 16) {
      Serial.println("Auth: encrypted payload too short");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    uint64_t sessionId = read48be(encrypted);
    uint64_t counter   = read48be(encrypted + 6);
    Serial.printf("Auth: IV sessionId=%012llX counter=%llu\n", (unsigned long long)sessionId, (unsigned long long)counter);

    if (!isCounterFresh(sessionId, counter)) {
      Serial.println("Auth: counter replay/stale");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    uint8_t decrypted[256];
    size_t decryptedLen = 0;
    if (!decryptAESGCM_from_bytes(encrypted, encryptedLen, decrypted, &decryptedLen)) {
      Serial.println("Auth: AES-GCM decryption failed");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }

    updateLastCounter(sessionId, counter);

    // Trim and NUL-terminate
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;
    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    Serial.print("Auth: decrypted ASCII: ");
    Serial.println(reinterpret_cast<char*>(decrypted));

    // Parse email|password|deviceid
    std::string s = reinterpret_cast<char*>(decrypted);
    size_t sep1 = s.find('|');
    size_t sep2 = (sep1 == std::string::npos) ? std::string::npos : s.find('|', sep1 + 1);
    if (sep1 == std::string::npos || sep2 == std::string::npos) {
      Serial.println("Auth: bad format — expected email|password|deviceid");
      std::string outHex;
      if (encryptAESGCM_packet("AUTH_FAIL", outHex)) {
        authChar->setValue(outHex);
        authChar->notify();
      }
      delay(200);
      //pBLEServer->disconnect(connId);
      return;
    }
    std::string email = s.substr(0, sep1);
    std::string password = s.substr(sep1 + 1, sep2 - (sep1 + 1));
    std::string deviceId = s.substr(sep2 + 1);
    Serial.printf("Auth attempt — email: %s deviceId: %s\n", email.c_str(), deviceId.c_str());

    bool okCreds = checkCredentials(email, password);
    bool okDevice = (deviceId.length() > 0 && deviceId.length() <= 40 && isDeviceRegistered(deviceId.c_str()));
    bool ok = okCreds && okDevice;
    if (ok) {
      authenticated = true;
      strncpy(connectedUserEmail, email.c_str(), sizeof(connectedUserEmail) - 1);
      connectedUserEmail[sizeof(connectedUserEmail) - 1] = '\0';
      Serial.printf("Authentication SUCCESS — user: %s device: %s\n", email.c_str(), deviceId.c_str());
    } else {
      authenticated = false;
      if (!okCreds) Serial.printf("Authentication FAILED (bad credentials) — user: %s\n", email.c_str());
      if (!okDevice) Serial.printf("Authentication FAILED (unregistered device) — device: %s\n", deviceId.c_str());
    }

    // Encrypt and send response
    std::string reply = ok ? "AUTH_OK" : "AUTH_FAIL";
    std::string outHex;
    if (encryptAESGCM_packet(reply, outHex)) {
      authChar->setValue(outHex);
      authChar->notify();
      Serial.print("Auth: sent encrypted reply HEX: ");
      Serial.println(outHex.c_str());
      Serial.print("Auth: sent encrypted reply ASCII (hex->bin shown as . if nonprintable): ");
      // print ascii-friendly view of reply hex
      for (char ch : outHex) Serial.write(ch);
      Serial.println();
    } else {
      Serial.println("Auth: failed to encrypt reply");
    }

    if (!ok) {
      delay(200);
      //pBLEServer->disconnect(connId);
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
    //logBLEReceivedData("HEARTBEAT write received", data);
    //Serial.printf("✓ Heartbeat received length=%u\n", (unsigned)data.length());
    
    if (data.length() == 0) {
      Serial.println("Heartbeat characteristic received EMPTY data");
      return;
    }

    uint8_t decrypted[32];
    size_t decryptedLen = 0;
    uint64_t sessionId = 0;
    uint64_t counter = 0;

    if (!decryptAndValidateEncryptedPayload(data, decrypted, &decryptedLen, sessionId, counter)) {
      Serial.println("Heartbeat decryption or validation failed");
      return;
    }

    // Trim trailing nulls if any
    while (decryptedLen > 0 && decrypted[decryptedLen - 1] == '\0') decryptedLen--;
    if (decryptedLen >= sizeof(decrypted)) decryptedLen = sizeof(decrypted) - 1;
    decrypted[decryptedLen] = '\0';

    //Serial.printf("Heartbeat decrypted: %s (sessionId=%012llX counter=%llu)\n",
     // reinterpret_cast<char*>(decrypted),
     // (unsigned long long)sessionId,
     // (unsigned long long)counter);

    if (strcmp(reinterpret_cast<char*>(decrypted), "HB") != 0) {
      Serial.printf("Heartbeat invalid content: %s\n", reinterpret_cast<char*>(decrypted));
      return;
    }

    lastHeartbeatTime = millis();
    heartbeatMissCount = 0;
    if (!heartbeatAlive) {
      heartbeatAlive = true;
      Serial.println("✓ Heartbeat restored — outputs re-enabled");
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
  BLEAdvertisementData advertData;
  advertData.setManufacturerData("PLC14");
  pAdvertising->setAdvertisementData(advertData);
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
