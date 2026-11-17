// siphash.h — SipHash-2-4 keyed message-authentication code.
//
// A small, fast MAC suitable for short messages on constrained MCUs (works on
// 8-bit AVR and on the ESP cores). Used by CyberShi / Sentinel Mesh to
// authenticate (a) inter-node verdicts over ESP-NOW and (b) the coordinator ->
// Arduino enforcement command over UART, so a forged or replayed message is
// rejected before any physical action is taken.
//
// Reference: J.-P. Aumasson & D. J. Bernstein, "SipHash: a fast short-input PRF"
// (INDOCRYPT 2012). This is a compact public-domain-style reference port.
//
// Assumes a little-endian host (true for ESP8266/ESP32 and AVR).
#pragma once
#include <stdint.h>
#include <string.h>

static inline uint64_t siphash24(const uint8_t *in, uint16_t inlen, const uint8_t key[16]) {
  uint64_t k0, k1;
  memcpy(&k0, key, 8);
  memcpy(&k1, key + 8, 8);

  uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
  uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
  uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
  uint64_t v3 = 0x7465646279746573ULL ^ k1;

  const uint8_t *end = in + (inlen - (inlen % 8));
  uint64_t b = ((uint64_t)inlen) << 56;

  #define SIP_ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
  #define SIP_ROUND()                         \
    do {                                      \
      v0 += v1; v1 = SIP_ROTL(v1, 13); v1 ^= v0; v0 = SIP_ROTL(v0, 32); \
      v2 += v3; v3 = SIP_ROTL(v3, 16); v3 ^= v2;                        \
      v0 += v3; v3 = SIP_ROTL(v3, 21); v3 ^= v0;                        \
      v2 += v1; v1 = SIP_ROTL(v1, 17); v1 ^= v2; v2 = SIP_ROTL(v2, 32); \
    } while (0)

  for (; in != end; in += 8) {
    uint64_t m;
    memcpy(&m, in, 8);
    v3 ^= m; SIP_ROUND(); SIP_ROUND(); v0 ^= m;
  }

  int left = inlen & 7;
  for (int i = 0; i < left; i++) b |= ((uint64_t)in[i]) << (8 * i);

  v3 ^= b; SIP_ROUND(); SIP_ROUND(); v0 ^= b;
  v2 ^= 0xff; SIP_ROUND(); SIP_ROUND(); SIP_ROUND(); SIP_ROUND();

  #undef SIP_ROTL
  #undef SIP_ROUND
  return v0 ^ v1 ^ v2 ^ v3;
}
