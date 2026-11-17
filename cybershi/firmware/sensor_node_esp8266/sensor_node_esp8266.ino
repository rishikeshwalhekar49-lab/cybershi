/* ============================================================================
 * CyberShi / Sentinel Mesh — Sensor Node 1  (ESP8266)
 * ----------------------------------------------------------------------------
 * Role: passive 802.11 detector. Sniffs management frames on a fixed channel
 * in promiscuous mode, scores them per attack class over a sliding window, and
 * broadcasts an AUTHENTICATED verdict to the mesh over ESP-NOW. It never
 * transmits attack frames and never joins a network.
 *
 * Boards: "NodeMCU 1.0 (ESP-12E)" / generic ESP8266. Powered over USB.
 *
 * NOTE: the ESP8266 promiscuous "sniffer buffer" layout is SDK-dependent. The
 * parsing below (rssi at buf[0], 802.11 frame at buf+12) matches the common
 * SDK layout used by well-known deauth-detector projects; verify on your SDK
 * version if counts look wrong. This is reference firmware — test on hardware.
 * ========================================================================== */

#include <ESP8266WiFi.h>
#include <espnow.h>
extern "C" {
  #include "user_interface.h"
}
#include "protocol.h"

// ---- configuration ----------------------------------------------------------
static const uint8_t  WIFI_CHANNEL = 6;      // all sensors + the test AP on ch 6
static const uint8_t  NODE_ID      = 1;
static const uint32_t WINDOW_MS    = 1000;   // scoring window

// thresholds (tune on your bench) — frames per window
static const uint16_t TH_DEAUTH    = 20;
static const uint16_t TH_DISASSOC  = 20;
static const uint16_t TH_BEACON    = 60;     // total beacons/window
static const uint8_t  TH_BSSIDS    = 12;     // distinct BSSIDs/window (beacon flood)
static const uint16_t TH_PROBEREQ  = 40;

static uint8_t broadcastMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// ---- per-window counters (written from the sniffer callback) ----------------
volatile uint16_t cDeauth, cDisassoc, cBeacon, cProbeReq, cProbeResp;
volatile int8_t   bestRssi = -128;

// small set of distinct BSSIDs seen this window (for beacon-flood detection)
#define BSSID_SET_MAX 32
static uint8_t bssidSet[BSSID_SET_MAX][6];
volatile uint8_t bssidCount = 0;

static bool bssidSeen(const uint8_t *b) {
  for (uint8_t i = 0; i < bssidCount; i++)
    if (memcmp(bssidSet[i], b, 6) == 0) return true;
  if (bssidCount < BSSID_SET_MAX) { memcpy(bssidSet[bssidCount++], b, 6); }
  return false;
}

static void resetWindow() {
  cDeauth = cDisassoc = cBeacon = cProbeReq = cProbeResp = 0;
  bestRssi = -128; bssidCount = 0;
}

// ---- promiscuous sniffer callback ------------------------------------------
// buf[0] = signed RSSI (RxControl); 802.11 MAC header begins at buf + 12.
// MAC header: FC(2) Dur(2) Addr1(6) Addr2/src(6) Addr3/bssid(6) SeqCtl(2).
static void ICACHE_FLASH_ATTR snifferCb(uint8_t *buf, uint16_t len) {
  if (len < 24 + 12) return;                 // need RxControl + a full MAC header
  int8_t  rssi  = (int8_t)buf[0];
  uint8_t *frm  = buf + 12;
  uint8_t  fc0  = frm[0];
  uint8_t  type = (fc0 & 0x0C) >> 2;         // 0 = management
  uint8_t  sub  = (fc0 & 0xF0) >> 4;
  if (type != 0) return;

  const uint8_t *bssid = frm + 16;           // Addr3
  if (rssi > bestRssi) bestRssi = rssi;

  switch (sub) {
    case 0x0C: cDeauth++;    break;          // deauthentication
    case 0x0A: cDisassoc++;  break;          // disassociation
    case 0x08: cBeacon++; bssidSeen(bssid);  break;  // beacon
    case 0x04: cProbeReq++;  break;          // probe request
    case 0x05: cProbeResp++; break;          // probe response (karma hint)
    default: break;
  }
  // NOTE: Evil-twin (one SSID on two BSSIDs) and karma (one BSSID answering many
  // SSIDs) need SSID extraction from the frame body + cross-frame correlation.
  // Hooks are left for the coordinator, which sees every node's view; see
  // sensor_node_esp32s3 and the README for the intended approach.
}

// ---- scoring ----------------------------------------------------------------
// Returns a class and a 0..255 confidence for this window.
static AttackClass scoreWindow(uint8_t &confidence) {
  confidence = 0;
  if (cDeauth >= TH_DEAUTH) {
    confidence = (uint8_t)min(255u, (unsigned)(cDeauth * 255u / (TH_DEAUTH * 3u) + 60));
    return CLS_DEAUTH;
  }
  if (cDisassoc >= TH_DISASSOC) {
    confidence = (uint8_t)min(255u, (unsigned)(cDisassoc * 255u / (TH_DISASSOC * 3u) + 60));
    return CLS_DISASSOC;
  }
  if (cBeacon >= TH_BEACON && bssidCount >= TH_BSSIDS) {
    confidence = (uint8_t)min(255u, (unsigned)(bssidCount * 255u / (TH_BSSIDS * 2u) + 60));
    return CLS_BEACON_FLOOD;
  }
  if (cProbeReq >= TH_PROBEREQ) {
    // kept deliberately conservative — ordinary devices scan a lot
    confidence = (uint8_t)min(200u, (unsigned)(cProbeReq * 200u / (TH_PROBEREQ * 3u) + 40));
    return CLS_PROBE_FLOOD;
  }
  return CLS_NONE;
}

// ---- ESP-NOW ----------------------------------------------------------------
static uint32_t txCounter = 0;

static void sendVerdict(AttackClass cls, uint8_t conf, int8_t rssi) {
  Verdict v;
  v.node_id    = NODE_ID;
  v.attack_cls = (uint8_t)cls;
  v.confidence = conf;
  v.rssi       = rssi;
  v.counter    = ++txCounter;
  sign_verdict(&v);                          // sets magic + SipHash MAC

  // ESP8266: promiscuous and ESP-NOW share one radio. Briefly leave
  // promiscuous, transmit, then resume sniffing.
  wifi_promiscuous_enable(0);
  esp_now_send(broadcastMac, (uint8_t *)&v, sizeof(v));
  wifi_promiscuous_enable(1);
}

// ---- setup / loop -----------------------------------------------------------
void setup() {
  Serial.begin(115200);
  Serial.println(F("\n[Node1/ESP8266] Sentinel Mesh sensor starting"));

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_set_channel(WIFI_CHANNEL);

  if (esp_now_init() != 0) { Serial.println(F("ESP-NOW init failed")); }
  esp_now_set_self_role(ESP_NOW_ROLE_COMBO);
  esp_now_add_peer(broadcastMac, ESP_NOW_ROLE_COMBO, WIFI_CHANNEL, NULL, 0);

  wifi_set_promiscuous_rx_cb(snifferCb);
  wifi_promiscuous_enable(1);
  resetWindow();
  Serial.println(F("Sniffing channel 6..."));
}

void loop() {
  static uint32_t lastWindow = 0;
  uint32_t now = millis();
  if (now - lastWindow < WINDOW_MS) { delay(5); return; }
  lastWindow = now;

  // snapshot + reset the window
  noInterrupts();
  uint16_t d = cDeauth, da = cDisassoc, bc = cBeacon, pr = cProbeReq;
  uint8_t  nb = bssidCount; int8_t r = bestRssi;
  interrupts();

  uint8_t conf;
  AttackClass cls = scoreWindow(conf);

  Serial.printf("win: deauth=%u disassoc=%u beacon=%u(bssids=%u) probe=%u rssi=%d -> cls=%u conf=%u\n",
                d, da, bc, nb, pr, r, (unsigned)cls, conf);

  if (cls != CLS_NONE) sendVerdict(cls, conf, r);
  resetWindow();
}
