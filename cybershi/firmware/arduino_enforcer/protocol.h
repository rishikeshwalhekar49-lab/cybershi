// protocol.h — shared message formats for the CyberShi / Sentinel Mesh system.
//
// Two authenticated message types:
//   Verdict  — a sensor node's scored opinion, broadcast over ESP-NOW.
//   Command  — the coordinator's enforcement order to the radio-free Arduino.
//
// Each message carries a strictly-increasing counter (replay protection) and a
// SipHash-2-4 MAC over everything before the mac field (authentication).
#pragma once
#include <stdint.h>
#include "siphash.h"

// ======================================================================
//  !!  CHANGE THESE KEYS BEFORE DEPLOYING  !!
//  KEY_MESH must be identical on every sensor node.
//  KEY_UART must be identical on the coordinator and the Arduino enforcer.
//  (16 random bytes each. The values below are placeholders.)
// ======================================================================
static const uint8_t KEY_MESH[16] = {
  0x53,0x65,0x6e,0x74,0x69,0x6e,0x65,0x6c, 0x4d,0x65,0x73,0x68,0x4b,0x65,0x79,0x31 };
static const uint8_t KEY_UART[16] = {
  0x45,0x6e,0x66,0x6f,0x72,0x63,0x65,0x72, 0x4c,0x69,0x6e,0x6b,0x4b,0x65,0x79,0x32 };

// Attack classes (kept in sync across all firmware).
enum AttackClass : uint8_t {
  CLS_NONE = 0, CLS_DEAUTH, CLS_DISASSOC, CLS_BEACON_FLOOD,
  CLS_PROBE_FLOOD, CLS_EVIL_TWIN, CLS_KARMA
};

// Enforcement operations.
enum CmdOp : uint8_t { OP_NORMAL = 0, OP_QUARANTINE = 1, OP_RELEASE = 2 };

#pragma pack(push, 1)
typedef struct {
  uint8_t  magic;       // 0x5A
  uint8_t  node_id;     // 1, 2, ...
  uint8_t  attack_cls;  // AttackClass
  uint8_t  confidence;  // 0..255  (255 = certain)
  int8_t   rssi;        // strongest RSSI of the offending frames (dBm)
  uint32_t counter;     // strictly increasing per node
  uint64_t mac;         // SipHash over the first VERDICT_SIGNED_LEN bytes, KEY_MESH
} Verdict;              // 17 bytes, broadcast over ESP-NOW

typedef struct {
  uint8_t  magic;       // 0xC0
  uint8_t  op;          // CmdOp
  uint8_t  target;      // protected-device id
  uint8_t  reason;      // AttackClass that triggered it
  uint32_t counter;     // strictly increasing
  uint64_t mac;         // SipHash over the first COMMAND_SIGNED_LEN bytes, KEY_UART
} Command;              // 16 bytes, coordinator -> Arduino over UART
#pragma pack(pop)

#define VERDICT_MAGIC       0x5A
#define COMMAND_MAGIC       0xC0
#define VERDICT_SIGNED_LEN  9   // magic .. counter  (everything before 'mac')
#define COMMAND_SIGNED_LEN  8   // magic .. counter

static inline void sign_verdict(Verdict *v) {
  v->magic = VERDICT_MAGIC;
  v->mac = siphash24((const uint8_t *)v, VERDICT_SIGNED_LEN, KEY_MESH);
}
static inline bool verify_verdict(const Verdict *v) {
  return v->magic == VERDICT_MAGIC &&
         v->mac == siphash24((const uint8_t *)v, VERDICT_SIGNED_LEN, KEY_MESH);
}
static inline void sign_command(Command *c) {
  c->magic = COMMAND_MAGIC;
  c->mac = siphash24((const uint8_t *)c, COMMAND_SIGNED_LEN, KEY_UART);
}
static inline bool verify_command(const Command *c) {
  return c->magic == COMMAND_MAGIC &&
         c->mac == siphash24((const uint8_t *)c, COMMAND_SIGNED_LEN, KEY_UART);
}
