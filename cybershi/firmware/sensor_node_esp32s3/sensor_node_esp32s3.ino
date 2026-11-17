/* ============================================================================
 * CyberShi / Sentinel Mesh — Sensor Node 2 + COORDINATOR  (ESP32-S3)
 * ----------------------------------------------------------------------------
 * Dual role:
 *   (1) Sensor — sniffs 802.11 management frames on channel 6 and scores them,
 *       exactly like Node 1.
 *   (2) Coordinator — collects AUTHENTICATED verdicts from the mesh over
 *       ESP-NOW, verifies each one (SipHash + strictly-increasing counter),
 *       combines them into an RSSI/confidence-weighted vote, runs the
 *       trust-score state machine, and sends an AUTHENTICATED enforcement
 *       command to the radio-free Arduino over UART.
 *
 * Board: "ESP32S3 Dev Module" (or your ESP32-S3 Mini). Powered over USB.
 * UART out: TX_PIN -> Arduino D2 (SoftwareSerial RX). Common ground required.
 *
 * ESP-NOW receive-callback signature follows ESP32 Arduino core 3.x
 * (esp_now_recv_info_t). On core 2.x use: void onRecv(const uint8_t*mac,...).
 * Reference firmware — verify on hardware.
 * ========================================================================== */

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "protocol.h"

// ---- configuration ----------------------------------------------------------
static const uint8_t  WIFI_CHANNEL = 6;
static const uint8_t  NODE_ID      = 2;
static const uint8_t  TARGET_DEV   = 1;      // id of the protected device
static const uint32_t WINDOW_MS    = 1000;
static const uint8_t  QUORUM       = 2;      // nodes that must agree
static const uint16_t WEIGHT_TH    = 400;    // weighted-score threshold to act
static const uint32_t COOLDOWN_MS  = 12000;  // quiet time before recovery
static const uint32_t RECOVER_MS   = 6000;   // re-verification window
static const uint32_t VERDICT_TTL  = 2500;   // a verdict is "fresh" this long

static const int TX_PIN = 17;                // -> Arduino D2
static const int RX_PIN = 18;                // unused (one-way link)

// thresholds (match Node 1)
static const uint16_t TH_DEAUTH=20, TH_DISASSOC=20, TH_BEACON=60, TH_PROBEREQ=40;
static const uint8_t  TH_BSSIDS=12;

// ---- local sniffer counters -------------------------------------------------
volatile uint16_t cDeauth, cDisassoc, cBeacon, cProbeReq, cProbeResp;
volatile int8_t   bestRssi = -128;
#define BSSID_SET_MAX 32
static uint8_t bssidSet[BSSID_SET_MAX][6];
volatile uint8_t bssidCount = 0;

static bool bssidSeen(const uint8_t *b){
  for(uint8_t i=0;i<bssidCount;i++) if(!memcmp(bssidSet[i],b,6)) return true;
  if(bssidCount<BSSID_SET_MAX) memcpy(bssidSet[bssidCount++],b,6);
  return false;
}
static void resetWindow(){ cDeauth=cDisassoc=cBeacon=cProbeReq=cProbeResp=0; bestRssi=-128; bssidCount=0; }

static void IRAM_ATTR promiscCb(void *buf, wifi_promiscuous_pkt_type_t type){
  if(type!=WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *frm = p->payload;
  uint8_t sub = (frm[0] & 0xF0) >> 4;
  int8_t  rssi = p->rx_ctrl.rssi;
  const uint8_t *bssid = frm + 16;
  if(rssi>bestRssi) bestRssi=rssi;
  switch(sub){
    case 0x0C: cDeauth++; break;
    case 0x0A: cDisassoc++; break;
    case 0x08: cBeacon++; bssidSeen(bssid); break;
    case 0x04: cProbeReq++; break;
    case 0x05: cProbeResp++; break;
    default: break;
  }
}

static AttackClass scoreWindow(uint8_t &conf){
  conf=0;
  if(cDeauth>=TH_DEAUTH){ conf=min(255,(int)(cDeauth*255/(TH_DEAUTH*3)+60)); return CLS_DEAUTH; }
  if(cDisassoc>=TH_DISASSOC){ conf=min(255,(int)(cDisassoc*255/(TH_DISASSOC*3)+60)); return CLS_DISASSOC; }
  if(cBeacon>=TH_BEACON && bssidCount>=TH_BSSIDS){ conf=min(255,(int)(bssidCount*255/(TH_BSSIDS*2)+60)); return CLS_BEACON_FLOOD; }
  if(cProbeReq>=TH_PROBEREQ){ conf=min(200,(int)(cProbeReq*200/(TH_PROBEREQ*3)+40)); return CLS_PROBE_FLOOD; }
  return CLS_NONE;
}

// ---- mesh: latest verdict per node -----------------------------------------
struct NodeView { bool used; uint8_t cls; uint8_t conf; int8_t rssi; uint32_t ctr; uint32_t t; };
#define MAX_NODES 8
static NodeView nodes[MAX_NODES];

static void storeVerdict(const Verdict *v){
  uint8_t id = v->node_id; if(id>=MAX_NODES) return;
  if(nodes[id].used && v->counter<=nodes[id].ctr) return;   // replay / stale
  nodes[id]={true,v->attack_cls,v->confidence,v->rssi,v->counter,millis()};
}

// ESP32 core 3.x signature:
static void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len){
  if(len!=sizeof(Verdict)) return;
  Verdict v; memcpy(&v,data,sizeof(v));
  if(!verify_verdict(&v)) return;                           // forged -> drop
  storeVerdict(&v);
}

static inline uint16_t rssiWeight(int8_t r){               // -90..-30 -> 1..10
  int w = map(r, -90, -30, 1, 10); return constrain(w,1,10);
}
static inline bool deviceTargeting(uint8_t cls){
  return cls==CLS_DEAUTH||cls==CLS_DISASSOC||cls==CLS_EVIL_TWIN||cls==CLS_KARMA;
}

// Tally fresh verdicts into a winning class. Returns weighted score; sets votes.
static AttackClass consensus(uint16_t &bestScore, uint8_t &votes){
  uint32_t w_sum[8]={0}; uint8_t v_cnt[8]={0};
  uint32_t now=millis();
  for(uint8_t i=0;i<MAX_NODES;i++){
    if(!nodes[i].used) continue;
    if(now-nodes[i].t>VERDICT_TTL){ nodes[i].used=false; continue; }
    uint8_t c=nodes[i].cls; if(c==CLS_NONE||c>=8) continue;
    w_sum[c]+= (uint32_t)rssiWeight(nodes[i].rssi)*nodes[i].conf;
    v_cnt[c]++;
  }
  AttackClass best=CLS_NONE; bestScore=0; votes=0;
  for(uint8_t c=1;c<8;c++) if(w_sum[c]>bestScore){ bestScore=w_sum[c]; best=(AttackClass)c; votes=v_cnt[c]; }
  return best;
}

// ---- enforcement over UART --------------------------------------------------
static uint32_t cmdCounter=0;
static void sendCommand(CmdOp op, uint8_t reason){
  Command c; c.op=op; c.target=TARGET_DEV; c.reason=reason; c.counter=++cmdCounter;
  sign_command(&c);
  Serial1.write((uint8_t*)&c, sizeof(c));
  Serial.printf("[UART] op=%u reason=%u ctr=%lu\n",(unsigned)op,reason,(unsigned long)c.counter);
}

// ---- trust-score state machine ----------------------------------------------
enum FsmState { S_NORMAL, S_SUSPICIOUS, S_QUARANTINED, S_RECOVERING };
static FsmState state=S_NORMAL;
static uint32_t stateSince=0, lastAttack=0, backoff=COOLDOWN_MS;

static void setState(FsmState s){ state=s; stateSince=millis(); }

void setup(){
  Serial.begin(115200);
  Serial1.begin(9600, SERIAL_8N1, RX_PIN, TX_PIN);   // TX_PIN -> Arduino D2
  Serial.println("\n[Node2/ESP32-S3] Coordinator starting");

  WiFi.mode(WIFI_STA); WiFi.disconnect();
  esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

  if(esp_now_init()!=ESP_OK){ Serial.println("ESP-NOW init failed"); }
  esp_now_register_recv_cb(onRecv);
  esp_now_peer_info_t peer{}; memset(peer.peer_addr,0xFF,6);
  peer.channel=WIFI_CHANNEL; peer.encrypt=false; esp_now_add_peer(&peer);

  esp_wifi_set_promiscuous_rx_cb(promiscCb);
  esp_wifi_set_promiscuous(true);
  resetWindow();
  sendCommand(OP_NORMAL, CLS_NONE);
  Serial.println("Sniffing + coordinating on channel 6...");
}

void loop(){
  static uint32_t lastWindow=0;
  uint32_t now=millis();
  if(now-lastWindow<WINDOW_MS){ delay(5); return; }
  lastWindow=now;

  // 1) inject this node's own local score as node 2's verdict
  uint8_t conf; AttackClass local=scoreWindow(conf);
  if(local!=CLS_NONE){
    Verdict self; self.magic=VERDICT_MAGIC; self.node_id=NODE_ID;
    self.attack_cls=(uint8_t)local; self.confidence=conf; self.rssi=bestRssi;
    self.counter=now; self.mac=0;               // local verdict, not MAC-checked
    storeVerdict(&self);
  }
  resetWindow();

  // 2) consensus
  uint16_t score; uint8_t votes;
  AttackClass cls = consensus(score, votes);
  bool attackNow = (cls!=CLS_NONE && votes>=QUORUM && score>=WEIGHT_TH);
  if(attackNow) lastAttack=now;

  Serial.printf("[consensus] cls=%u votes=%u score=%u state=%u\n",(unsigned)cls,votes,score,(unsigned)state);

  // 3) state machine
  switch(state){
    case S_NORMAL:
      if(attackNow){
        if(deviceTargeting(cls)){ sendCommand(OP_QUARANTINE, cls); setState(S_QUARANTINED); }
        else { /* environmental: alert + localize only, never quarantine */
          Serial.printf("[ALERT] environmental attack cls=%u (flag + RSSI-localize, no quarantine)\n",(unsigned)cls);
        }
      }
      break;
    case S_QUARANTINED:
      if(now-lastAttack>=backoff){ sendCommand(OP_RELEASE, cls); setState(S_RECOVERING); }
      break;
    case S_RECOVERING:
      if(attackNow && deviceTargeting(cls)){     // re-attacked: re-quarantine, back off harder
        backoff = min<uint32_t>(backoff*2, 120000);
        sendCommand(OP_QUARANTINE, cls); setState(S_QUARANTINED);
      } else if(now-stateSince>=RECOVER_MS){
        sendCommand(OP_NORMAL, CLS_NONE); backoff=COOLDOWN_MS; setState(S_NORMAL);
      }
      break;
    default: break;
  }
}
