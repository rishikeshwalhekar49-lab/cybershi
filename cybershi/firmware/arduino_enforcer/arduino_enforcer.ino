/* ============================================================================
 * CyberShi / Sentinel Mesh — Radio-free ENFORCER  (Arduino UNO)
 * ----------------------------------------------------------------------------
 * The actuator with NO radio. Its only input is a one-way serial line from the
 * coordinator (coordinator TX -> D2, with a shared ground). It verifies every
 * command (SipHash MAC + strictly-increasing counter) before acting, then trips
 * the relay to cut the protected device's power, drives the LCD / LEDs / buzzer,
 * reads the ACS712 to confirm the power state, and auto-recovers.
 *
 * Because it has no wireless interface, the attack it is stopping cannot reach
 * it, and a forged or replayed byte on D2 is rejected by the MAC + counter.
 *
 * Wiring (see /hardware):
 *   D2  <- coordinator TX (SoftwareSerial RX)      A4/A5 -> 16x2 I2C LCD
 *   D7  -> relay IN1 (channel 1 = device power)    A0    <- ACS712 OUT
 *   D8  -> buzzer (+)    D9 -> green LED    D10 -> red LED
 *
 * Libraries: LiquidCrystal_I2C, SoftwareSerial (bundled). Reference firmware.
 * ========================================================================== */

#include <SoftwareSerial.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include "protocol.h"

// ---- pins -------------------------------------------------------------------
static const uint8_t PIN_RX     = 2;   // from coordinator TX
static const uint8_t PIN_RELAY1 = 7;   // device power
static const uint8_t PIN_BUZZER = 8;
static const uint8_t PIN_LED_G  = 9;   // NORMAL
static const uint8_t PIN_LED_R  = 10;  // ALERT / quarantined
static const uint8_t PIN_ACS712 = A0;

// Relay module polarity. Most 4-channel boards are ACTIVE-LOW.
// "Cut power" = energise the relay so its NC contact opens.
static const uint8_t RELAY_ON  = LOW;   // energised (device power CUT)
static const uint8_t RELAY_OFF = HIGH;  // idle (device powered via NC)

static const uint32_t SAFETY_RELEASE_MS = 60000; // auto-restore if RELEASE is missed

SoftwareSerial link(PIN_RX, 3);   // TX pin unused (the link is one-way)
LiquidCrystal_I2C lcd(0x27, 16, 2);

static uint32_t lastCounter = 0;
static uint32_t quarantinedAt = 0;
static bool     quarantined = false;
static int      acsBaseline = 512;     // ~Vcc/2 at idle

// ---- actuation --------------------------------------------------------------
static void showStatus(const char *line1, const char *line2) {
  lcd.clear(); lcd.setCursor(0,0); lcd.print(line1);
  lcd.setCursor(0,1); lcd.print(line2);
}

static const char* clsName(uint8_t c){
  switch(c){ case CLS_DEAUTH:return "DEAUTH"; case CLS_DISASSOC:return "DISASSOC";
    case CLS_EVIL_TWIN:return "EVIL TWIN"; case CLS_KARMA:return "KARMA";
    case CLS_BEACON_FLOOD:return "BEACON"; case CLS_PROBE_FLOOD:return "PROBE"; default:return "-"; }
}

static void quarantine(uint8_t reason){
  digitalWrite(PIN_RELAY1, RELAY_ON);          // cut the device's power
  digitalWrite(PIN_LED_R, HIGH); digitalWrite(PIN_LED_G, LOW);
  tone(PIN_BUZZER, 2200, 400);
  char l2[17]; snprintf(l2,sizeof(l2),"ATK: %s", clsName(reason));
  showStatus("QUARANTINED", l2);
  quarantined = true; quarantinedAt = millis();
  Serial.print(F("QUARANTINE reason=")); Serial.println(clsName(reason));
}

static void restore(){
  digitalWrite(PIN_RELAY1, RELAY_OFF);         // power the device
  digitalWrite(PIN_LED_G, HIGH); digitalWrite(PIN_LED_R, LOW);
  noTone(PIN_BUZZER);
  showStatus("NORMAL", "device powered");
  quarantined = false;
  Serial.println(F("RESTORE"));
}

// ---- ACS712: confirm the power state ---------------------------------------
static int readCurrentRaw(){
  long acc=0; for(uint8_t i=0;i<16;i++){ acc+=analogRead(PIN_ACS712); delayMicroseconds(200); }
  return (int)(acc/16);
}

// ---- command handling -------------------------------------------------------
static void handle(const Command *c){
  if(!verify_command(c)){ Serial.println(F("drop: bad MAC")); return; }   // forged
  if(c->counter <= lastCounter){ Serial.println(F("drop: replay")); return; } // replay
  lastCounter = c->counter;

  switch(c->op){
    case OP_QUARANTINE: quarantine(c->reason); break;
    case OP_RELEASE:
    case OP_NORMAL:     restore(); break;
    default: break;
  }
  // corroborate with the current sensor
  int cur = readCurrentRaw();
  int dev = cur - acsBaseline;
  Serial.print(F("ACS712 raw=")); Serial.print(cur);
  Serial.print(F(" dev=")); Serial.println(dev);
}

// ---- frame reassembly (sync on magic, then read the rest) -------------------
static uint8_t rxbuf[sizeof(Command)];
static uint8_t rxIdx = 0;

static void pump(){
  while(link.available()){
    uint8_t b = link.read();
    if(rxIdx==0){ if(b==COMMAND_MAGIC) rxbuf[rxIdx++]=b; }
    else {
      rxbuf[rxIdx++]=b;
      if(rxIdx==sizeof(Command)){ handle((const Command*)rxbuf); rxIdx=0; }
    }
  }
}

void setup(){
  Serial.begin(115200);
  link.begin(9600);
  pinMode(PIN_RELAY1,OUTPUT); pinMode(PIN_BUZZER,OUTPUT);
  pinMode(PIN_LED_G,OUTPUT);  pinMode(PIN_LED_R,OUTPUT);
  lcd.init(); lcd.backlight();
  acsBaseline = readCurrentRaw();
  restore();                                   // start powered / NORMAL
  Serial.println(F("[Enforcer/UNO] radio-free enforcer ready"));
}

void loop(){
  pump();
  // safety net: if a RELEASE was lost, auto-restore after a timeout
  if(quarantined && (millis()-quarantinedAt > SAFETY_RELEASE_MS)){
    Serial.println(F("safety auto-release"));
    restore();
  }
}
