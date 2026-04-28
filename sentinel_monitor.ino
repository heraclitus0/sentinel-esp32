#include <WiFi.h>
#include <WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ---------------- OLED / LED CONFIG ----------------
#define RED_LED_PIN    2
#define GREEN_LED_PIN  4

#define OLED_SDA       21
#define OLED_SCL       22
#define SCREEN_WIDTH   128
#define SCREEN_HEIGHT  64
#define OLED_RESET     -1
#define OLED_ADDR      0x3C

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ---------------- SETUP PORTAL CONFIG ----------------
const char* CONFIG_AP_SSID = "Sentinel-Setup";
const char* CONFIG_AP_PASS = "12345678";   // minimum 8 chars for ESP32 softAP

WebServer server(80);

// session-only credentials in RAM
String activeSSID = "";
String activePASS = "";

// ---------------- MODES ----------------
enum DeviceMode {
  MODE_SETUP,
  MODE_MONITOR
};
DeviceMode deviceMode = MODE_SETUP;

// ---------------- MONITOR STATES ----------------
enum MonitorState {
  STATE_NO_WIFI,
  STATE_STABLE,
  STATE_SUSPICIOUS,
  STATE_ATTACK
};
MonitorState currentState = STATE_NO_WIFI;
MonitorState lastRenderedState = (MonitorState)(-1);

// ---------------- TIMING ----------------
const unsigned long WINDOW_MS           = 10000; // long window
const unsigned long BURST_WINDOW_MS     = 3000;  // short burst window
const unsigned long RECOVERY_MS         = 15000; // stable connected time before full STABLE
const unsigned long STATUS_PRINT_MS     = 2000;
const unsigned long WIFI_RETRY_MS       = 3000;
const unsigned long GREEN_BLINK_MS      = 700;
const unsigned long RED_SLOW_BLINK_MS   = 600;

// threat hold / outage logic
const unsigned long SUSPICIOUS_HOLD_MS  = 5000;
const unsigned long ATTACK_HOLD_MS      = 8000;
const unsigned long ATTACK_OUTAGE_MS    = 5000;

const int ATTACK_RECONNECT_FAILS        = 2;
const int SUSPICIOUS_RECONNECT_FAILS    = 1;

// ---------------- TRACKING ----------------
unsigned long windowStart         = 0;
unsigned long burstWindowStart    = 0;
unsigned long stableStart         = 0;
unsigned long lastStatusPrint     = 0;
unsigned long lastReconnectAttempt = 0;
unsigned long lastBlinkToggle     = 0;

bool greenLedState = false;
bool redLedState   = false;
bool wasConnected  = false;

int dropCountWindow    = 0;
int dropCountBurst     = 0;
int totalDisconnects   = 0;

// added evidence / memory
int failedReconnects       = 0;
unsigned long disconnectedSince = 0;
unsigned long threatHoldUntil   = 0;

// ---------------- HELPERS ----------------
const char* stateToString(MonitorState s) {
  switch (s) {
    case STATE_NO_WIFI:    return "NO WIFI";
    case STATE_STABLE:     return "STABLE";
    case STATE_SUSPICIOUS: return "SUSPICIOUS";
    case STATE_ATTACK:     return "ATTACK";
    default:               return "UNKNOWN";
  }
}

const char* linkQualityFromRSSI(int rssi) {
  if (rssi >= -67) return "GOOD";
  if (rssi >= -75) return "MID";
  return "POOR";
}

bool isConnectedNow() {
  return WiFi.status() == WL_CONNECTED;
}

int safeRSSI() {
  if (!isConnectedNow()) return -127;
  return WiFi.RSSI();
}

MonitorState evaluateConnectedState(int dropsLong, int dropsBurst, int rssi) {
  bool poor = (rssi < -75);

  // burst logic first
  if (dropsBurst >= 2) {
    return STATE_ATTACK;
  }
  if (dropsBurst == 1) {
    return STATE_SUSPICIOUS;
  }

  // sustained logic
  if (dropsLong <= 1) return STATE_STABLE;

  if (dropsLong >= 4) {
    if (poor) return STATE_SUSPICIOUS;
    return STATE_ATTACK;
  }

  if (dropsLong >= 2) return STATE_SUSPICIOUS;

  return STATE_STABLE;
}

// ---------------- OLED RENDERING ----------------
void renderSetupOLED(const String& msg1, const String& msg2 = "") {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(2);
  display.setCursor(0, 0);
  display.println("SETUP");

  display.setTextSize(1);
  display.setCursor(0, 24);
  display.println(msg1);

  if (msg2.length() > 0) {
    display.setCursor(0, 36);
    display.println(msg2);
  }

  display.display();
}

void renderOLED(MonitorState state, int dropsLong, int dropsBurst, int rssi) {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(2);
  display.setCursor(0, 0);
  display.println(stateToString(state));

  display.setTextSize(1);
  display.setCursor(0, 24);

  display.print("WiFi: ");
  display.println(isConnectedNow() ? "CONNECTED" : "DISCONNECTED");

  display.print("10s:");
  display.print(dropsLong);
  display.print(" 3s:");
  display.println(dropsBurst);

  display.print("RSSI: ");
  if (rssi == -127) {
    display.println("N/A");
  } else {
    display.print(rssi);
    display.print(" ");
    display.println(linkQualityFromRSSI(rssi));
  }

  display.display();
}

// ---------------- SERIAL ----------------
void printBootBanner() {
  Serial.println();
  Serial.println("[BOOT] ESP32 Session Disruption Monitor");
  Serial.println("[BOOT] OLED: SSD1306 @ 0x3C");
  Serial.println("[BOOT] Logic:");
  Serial.println(" NO WIFI -> Green blink");
  Serial.println(" STABLE -> Green solid");
  Serial.println(" SUSPICIOUS -> Red slow blink");
  Serial.println(" ATTACK -> Red solid");
  Serial.println("[BOOT] Detection:");
  Serial.println(" Burst window: 3 sec");
  Serial.println(" Long window : 10 sec");
  Serial.println(" Reconnect-failure aware");
  Serial.println(" Threat hold enabled");
  Serial.println("[BOOT] RSSI used only as link-quality context");
  Serial.println("[BOOT] Setup mode uses AP + webpage, no credential saving");
}

void printTransition(MonitorState from, MonitorState to) {
  Serial.print("[TRANSITION] ");
  Serial.print(stateToString(from));
  Serial.print(" -> ");
  Serial.println(stateToString(to));
}

void printStatus() {
  int rssi = safeRSSI();

  Serial.print("[STATE] ");
  Serial.print(stateToString(currentState));
  Serial.print(" | Connected: ");
  Serial.print(isConnectedNow() ? "YES" : "NO");
  Serial.print(" | Drops(10s): ");
  Serial.print(dropCountWindow);
  Serial.print(" | Drops(3s): ");
  Serial.print(dropCountBurst);
  Serial.print(" | TotalDrops: ");
  Serial.print(totalDisconnects);
  Serial.print(" | FailedReconnects: ");
  Serial.print(failedReconnects);
  Serial.print(" | RSSI: ");

  if (rssi == -127) {
    Serial.println("N/A");
  } else {
    Serial.print(rssi);
    Serial.print(" (");
    Serial.print(linkQualityFromRSSI(rssi));
    Serial.println(")");
  }
}

// ---------------- LED HANDLING ----------------
void handleLEDs(MonitorState state) {
  unsigned long now = millis();

  switch (state) {
    case STATE_NO_WIFI:
      digitalWrite(RED_LED_PIN, LOW);
      redLedState = false;

      if (now - lastBlinkToggle >= GREEN_BLINK_MS) {
        lastBlinkToggle = now;
        greenLedState = !greenLedState;
        digitalWrite(GREEN_LED_PIN, greenLedState ? HIGH : LOW);
      }
      break;

    case STATE_STABLE:
      digitalWrite(RED_LED_PIN, LOW);
      redLedState = false;
      digitalWrite(GREEN_LED_PIN, HIGH);
      greenLedState = true;
      break;

    case STATE_SUSPICIOUS:
      digitalWrite(GREEN_LED_PIN, LOW);
      greenLedState = false;

      if (now - lastBlinkToggle >= RED_SLOW_BLINK_MS) {
        lastBlinkToggle = now;
        redLedState = !redLedState;
        digitalWrite(RED_LED_PIN, redLedState ? HIGH : LOW);
      }
      break;

    case STATE_ATTACK:
      digitalWrite(GREEN_LED_PIN, LOW);
      greenLedState = false;
      digitalWrite(RED_LED_PIN, HIGH);
      redLedState = true;
      break;
  }
}

// ---------------- MONITOR ENGINE CONTROL ----------------
void resetMonitorCounters() {
  unsigned long now = millis();

  windowStart = now;
  burstWindowStart = now;
  stableStart = now;
  lastStatusPrint = now;
  lastBlinkToggle = now;

  dropCountWindow = 0;
  dropCountBurst = 0;
  totalDisconnects = 0;
  failedReconnects = 0;
  disconnectedSince = 0;
  threatHoldUntil = 0;
  wasConnected = false;

  currentState = STATE_NO_WIFI;
  lastRenderedState = (MonitorState)(-1);
}

void connectWiFi(const String& ssid, const String& pass) {
  Serial.print("[BOOT] Connecting to SSID: ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  delay(500);
  WiFi.begin(ssid.c_str(), pass.c_str());
}

void startMonitorMode() {
  deviceMode = MODE_MONITOR;
  resetMonitorCounters();
  Serial.println("[MODE] MONITOR");
}

void startSetupMode() {
  deviceMode = MODE_SETUP;

  WiFi.disconnect(true, true);
  delay(300);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(CONFIG_AP_SSID, CONFIG_AP_PASS);

  IPAddress apIP = WiFi.softAPIP();

  Serial.println();
  Serial.println("[MODE] SETUP AP started");
  Serial.print("[MODE] SSID: ");
  Serial.println(CONFIG_AP_SSID);
  Serial.print("[MODE] Password: ");
  Serial.println(CONFIG_AP_PASS);
  Serial.print("[MODE] Setup page: http://");
  Serial.println(apIP);
  Serial.println("[MODE] If click does not work, type this in browser:");
  Serial.println("http://192.168.4.1");

  renderSetupOLED("Join Sentinel-Setup", "Open 192.168.4.1");
}

// ---------------- HTML ----------------
String htmlEscape(const String& s) {
  String out = s;
  out.replace("&", "&amp;");
  out.replace("<", "&lt;");
  out.replace(">", "&gt;");
  out.replace("\"", "&quot;");
  return out;
}

String buildScanPage(const String& statusMsg = "") {
  int n = WiFi.scanNetworks();

  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel Setup</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h2 { margin-bottom: 8px; }
    .note { color: #444; margin-bottom: 12px; }
    .status { padding: 10px; background: #f1f1f1; margin-bottom: 12px; border-radius: 8px; }
    .net { padding: 8px; border: 1px solid #ddd; margin-bottom: 8px; border-radius: 8px; }
    input[type=password] { width: 100%; padding: 10px; margin-top: 10px; margin-bottom: 10px; }
    button { padding: 10px 14px; }
    .rssi { color: #666; font-size: 0.95em; }
  </style>
</head>
<body>
  <h2>Sentinel Wi-Fi Setup</h2>
  <div class="note">Refresh this page to rescan nearby networks.</div>
)rawliteral";

  if (statusMsg.length() > 0) {
    html += "<div class='status'>" + htmlEscape(statusMsg) + "</div>";
  }

  html += "<form method='POST' action='/connect'>";

  if (n <= 0) {
    html += "<p>No networks found.</p>";
  } else {
    for (int i = 0; i < n; i++) {
      String ssid = WiFi.SSID(i);
      int rssi = WiFi.RSSI(i);
      wifi_auth_mode_t enc = WiFi.encryptionType(i);

      html += "<div class='net'>";
      html += "<label>";
      html += "<input type='radio' name='ssid' value='" + htmlEscape(ssid) + "'";
      if (i == 0) html += " checked";
      html += "> ";
      html += "<strong>" + htmlEscape(ssid) + "</strong>";
      html += "</label><br>";
      html += "<span class='rssi'>RSSI: " + String(rssi) + " dBm";
      html += " | ";
      html += (enc == WIFI_AUTH_OPEN ? "OPEN" : "SECURED");
      html += "</span>";
      html += "</div>";
    }
  }

  html += R"rawliteral(
  <input type='password' name='pass' placeholder='Enter password'>
  <button type='submit'>Connect</button>
</form>
<p><a href="/">Rescan networks</a></p>
</body>
</html>
)rawliteral";

  return html;
}

// ---------------- WEB ROUTES ----------------
void handleRoot() {
  renderSetupOLED("Scanning networks...");
  server.send(200, "text/html", buildScanPage());
  renderSetupOLED("Join Sentinel-Setup", "Open 192.168.4.1");
}

void handleConnect() {
  if (!server.hasArg("ssid")) {
    server.send(400, "text/html", buildScanPage("No SSID selected."));
    return;
  }

  String ssid = server.arg("ssid");
  String pass = server.arg("pass");

  if (ssid.length() == 0) {
    server.send(400, "text/html", buildScanPage("SSID was empty."));
    return;
  }

  activeSSID = ssid;
  activePASS = pass;

  renderSetupOLED("Connecting to:", ssid);

  Serial.print("[SETUP] User selected SSID: ");
  Serial.println(ssid);

  WiFi.softAPdisconnect(true);
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  delay(500);
  WiFi.begin(activeSSID.c_str(), activePASS.c_str());

  unsigned long startAttempt = millis();
  bool ok = false;

  while (millis() - startAttempt < 15000) {
    delay(300);
    if (WiFi.status() == WL_CONNECTED) {
      ok = true;
      break;
    }
  }

  if (ok) {
    String msg = "Connected to " + activeSSID + " | IP: " + WiFi.localIP().toString();

    Serial.println("[SETUP] WiFi connection success");
    Serial.println(msg);

    server.send(
      200,
      "text/html",
      "<html><body><h3>Connected</h3><p>" + htmlEscape(msg) +
      "</p><p>Device entering monitor mode.</p></body></html>"
    );

    delay(800);
    startMonitorMode();
  } else {
    Serial.println("[SETUP] WiFi connection failed");
    startSetupMode();
    server.send(200, "text/html", buildScanPage("Connection failed. Refresh rescans."));
  }
}

void setupRoutes() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/connect", HTTP_POST, handleConnect);
  server.begin();
  Serial.println("[SETUP] Web server started");
}

// ---------------- MONITOR LOOP ----------------
void runMonitorLoop() {
  unsigned long now = millis();
  bool connected = isConnectedNow();

  if (connected && !wasConnected) {
    Serial.print("[EVENT] Connected | IP: ");
    Serial.println(WiFi.localIP());
    stableStart = now;
    failedReconnects = 0;
    disconnectedSince = 0;
  }

  if (!connected && wasConnected) {
    totalDisconnects++;
    dropCountWindow++;
    dropCountBurst++;
    disconnectedSince = now;

    Serial.print("[EVENT] Disconnected | 10sDrops: ");
    Serial.print(dropCountWindow);
    Serial.print(" | 3sDrops: ");
    Serial.print(dropCountBurst);
    Serial.print(" | TotalDisconnects: ");
    Serial.println(totalDisconnects);
  }

  wasConnected = connected;

  if (!connected && (now - lastReconnectAttempt >= WIFI_RETRY_MS)) {
    lastReconnectAttempt = now;
    failedReconnects++;

    Serial.print("[EVENT] Reconnect attempt... | FailedReconnects: ");
    Serial.println(failedReconnects);

    WiFi.disconnect();
    delay(200);
    WiFi.begin(activeSSID.c_str(), activePASS.c_str());
  }

  if (now - windowStart >= WINDOW_MS) {
    windowStart = now;
    dropCountWindow = 0;
  }

  if (now - burstWindowStart >= BURST_WINDOW_MS) {
    burstWindowStart = now;
    dropCountBurst = 0;
  }

  MonitorState evaluated;
  int rssi = safeRSSI();
  unsigned long outageMs = (disconnectedSince > 0) ? (now - disconnectedSince) : 0;

  if (!connected) {
    if (dropCountBurst >= 2 || (failedReconnects >= ATTACK_RECONNECT_FAILS && outageMs >= ATTACK_OUTAGE_MS)) {
      evaluated = STATE_ATTACK;
      threatHoldUntil = now + ATTACK_HOLD_MS;
    } else if (dropCountBurst == 1 || dropCountWindow >= 2 || failedReconnects >= SUSPICIOUS_RECONNECT_FAILS) {
      evaluated = STATE_SUSPICIOUS;
      if (threatHoldUntil < now + SUSPICIOUS_HOLD_MS) {
        threatHoldUntil = now + SUSPICIOUS_HOLD_MS;
      }
    } else if (now < threatHoldUntil) {
      evaluated = (currentState == STATE_ATTACK) ? STATE_ATTACK : STATE_SUSPICIOUS;
    } else {
      evaluated = STATE_NO_WIFI;
    }
  } else {
    evaluated = evaluateConnectedState(dropCountWindow, dropCountBurst, rssi);

    if (evaluated == STATE_ATTACK) {
      threatHoldUntil = now + ATTACK_HOLD_MS;
    } else if (evaluated == STATE_SUSPICIOUS) {
      if (threatHoldUntil < now + SUSPICIOUS_HOLD_MS) {
        threatHoldUntil = now + SUSPICIOUS_HOLD_MS;
      }
    } else if (now < threatHoldUntil) {
      evaluated = (currentState == STATE_ATTACK) ? STATE_ATTACK : STATE_SUSPICIOUS;
    }

    if (evaluated == STATE_STABLE) {
      if (now - stableStart < RECOVERY_MS) {
        if (currentState == STATE_ATTACK || currentState == STATE_SUSPICIOUS) {
          evaluated = STATE_SUSPICIOUS;
        }
      }
    }
  }

  if (evaluated != currentState) {
    printTransition(currentState, evaluated);
    currentState = evaluated;
  }

  handleLEDs(currentState);

  if (currentState != lastRenderedState || (now - lastStatusPrint >= STATUS_PRINT_MS)) {
    renderOLED(currentState, dropCountWindow, dropCountBurst, rssi);
    lastRenderedState = currentState;
  }

  if (now - lastStatusPrint >= STATUS_PRINT_MS) {
    lastStatusPrint = now;
    printStatus();
  }
}

// ---------------- SETUP ----------------
void setup() {
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);

  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);

  Serial.begin(115200);
  delay(700);

  printBootBanner();

  Wire.begin(OLED_SDA, OLED_SCL);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("[ERROR] OLED init failed");
    while (true) {
      digitalWrite(RED_LED_PIN, HIGH);
      delay(100);
      digitalWrite(RED_LED_PIN, LOW);
      delay(100);
    }
  }

  display.clearDisplay();
  display.display();

  startSetupMode();
  setupRoutes();
}

// ---------------- LOOP ----------------
void loop() {
  if (deviceMode == MODE_SETUP) {
    server.handleClient();

    // keep green blinking in setup as visible "not monitoring / not connected"
    handleLEDs(STATE_NO_WIFI);
    return;
  }

  runMonitorLoop();
}