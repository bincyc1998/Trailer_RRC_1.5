#pragma once

#include <Arduino.h>
#include <WebServer.h>
#include <Preferences.h>

// -------- Web admin credentials (mutable, stored in NVS namespace "webadmin") --------
// Defaults used on first boot; changed via the Account tab in the web UI.

// -------- BLE user store --------
#define MAX_USERS 10

struct User {
  char name[64];
  char email[64];
  char password[64];
  char role[32];
};

// Registered mobile devices
#define MAX_DEVICES 20
struct Device {
  char id[41]; // up to 40 chars + NUL
  char owner[64]; // optional owner email
};

// Shared globals defined in main.cpp
extern User        users[MAX_USERS];
extern int         userCount;
extern WebServer   webServer;
extern Preferences prefs;



// BLE connection state — defined in main.cpp
extern bool deviceConnected;
extern bool authenticated;
extern char connectedUserEmail[64];

// Current motion output state — defined in main.cpp, updated by BLE callback
extern bool motionEstop;
extern bool motionUp;
extern bool motionDown;
extern bool motionLeft;
extern bool motionRight;

// Output pin configuration — defined in main.cpp
#define NUM_OUTPUT_PINS 5
#define MOTION_NONE   0
#define MOTION_ESTOP  1
#define MOTION_UP     2
#define MOTION_DOWN   3
#define MOTION_LEFT   4
#define MOTION_RIGHT  5

struct OutPin {
  const char* label;
  int         pin;
};

// Output configuration for each output pin
struct PinMotion {
  uint8_t function; // 0=DF1, 1=DF2, 2=DF3, 3=DF4, 4=DF5
  uint8_t motion;   // 0=None, 1=ESTOP, 2=UP, 3=DOWN, 4=LEFT, 5=RIGHT
};

extern const OutPin OUTPUT_PINS[NUM_OUTPUT_PINS];
extern const char* OUTPUT_FUNCTIONS[NUM_OUTPUT_PINS];
extern PinMotion pinMotionConfig[NUM_OUTPUT_PINS];  // Maps each output pin to a digital function and motion

// BLE / WiFi credentials — defined in main.cpp
extern char bleName[32];
extern char wifiSsid[32];
extern char wifiPassword[64];

// NVS helpers defined in main.cpp, called from web handlers
void saveUsers();
void saveOutputConfig();
void applyOutputConfig();
void saveNetworkConfig();
void loadNetworkConfig();

// Web route registration — call once in setup()
void setupWebRoutes();

// Device registry helpers
extern Device devices[MAX_DEVICES];
extern int deviceCount;
void loadDevices();
void saveDevices();
bool isDeviceRegistered(const char* id);
bool registerDevice(const char* id, const char* owner);
bool unregisterDevice(const char* id);

// Motion helpers
const char* getMotionLabel(uint8_t motionId);
uint8_t getMotionIdForLabel(const char* label);
