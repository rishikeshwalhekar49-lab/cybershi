# CyberShi — Sentinel Mesh

**A distributed Wi-Fi intrusion-detection system that doesn't just detect attacks — it agrees one is happening and physically stops it.**

A small mesh of low-cost ESP32/ESP8266 nodes listens to 802.11 management frames in promiscuous mode, scores six classes of Wi-Fi attack, and reaches an **RSSI/confidence-weighted consensus** over a router-independent **ESP-NOW** mesh. When a quorum of nodes agrees, the coordinator sends a **cryptographically authenticated** command over a wired link to a deliberately **radio-free Arduino enforcer**, which physically **quarantines** the attacked device by cutting its power and then **auto-recovers** once the threat clears.

The enforcer has no radio of its own, so the attack it is stopping can never reach it, and it acts only on authenticated, replay-protected, multi-node agreement.

> Built as a student research project at Vishwakarma University, Pune, and exhibited at the Nexora 2026 innovation exhibition.

---

## How it works

```
  OVER THE AIR (no wires)                         WIRED / OUT-OF-BAND
  ┌──────────────┐   ESP-NOW    ┌───────────────┐   signed UART   ┌──────────────────┐
  │ Sensor Node 1│◄────────────►│ Sensor Node 2 │────────────────►│  Arduino UNO      │
  │  ESP8266     │  (vote)      │  ESP32-S3     │   (command)     │  radio-free       │
  │  sniff+score │              │  COORDINATOR  │                 │  enforcer         │
  └──────────────┘              └───────────────┘                 │  relay/LCD/LED/   │
                                                                   │  buzzer/ACS712    │
                                                                   └──────────────────┘
```

1. Each node sniffs channel 6, parses management frames, and scores them per window.
2. A node that sees an attack broadcasts a **signed verdict** (class, confidence, RSSI, counter, MAC) over ESP-NOW.
3. The coordinator verifies each verdict (SipHash + strictly-increasing counter) and computes a **weighted vote**.
4. If a quorum (≥ 2 nodes) agrees, the **trust-score state machine** advances and a **signed command** goes to the Arduino over UART.
5. The Arduino verifies the command, trips the relay to cut the victim's power, and raises the alarm.
6. After a cooldown with the air quiet, it **auto-recovers** — power is restored, state returns to normal.

**Device-targeting attacks** (deauth, disassoc, evil twin, karma) are *quarantined*. **Environmental attacks** (beacon flood, probe-flood reconnaissance) are *flagged and RSSI-localized*, not cut — there is no single victim to quarantine.

---

## Repository layout

```
cybershi/
├── firmware/
│   ├── sensor_node_esp8266/     # Node 1 — promiscuous sniffer + ESP-NOW verdicts
│   ├── sensor_node_esp32s3/     # Node 2 — sensor + coordinator + UART enforcement
│   ├── arduino_enforcer/        # radio-free actuator (relay/LCD/LED/buzzer/ACS712)
│   └── common/                  # siphash.h + protocol.h (copied into each sketch)
├── hardware/                    # wiring schematic, pin map, bill of materials
├── attack-testing/              # how to run each attack with established tools (for authorised testing)
└── docs/                        # project report and references
```

---

## The six attack classes

| # | Attack | Frame | Response |
|---|--------|-------|----------|
| 1 | Deauthentication flood | 0x0C | Quarantine |
| 2 | Disassociation flood | 0x0A | Quarantine |
| 3 | Beacon flood / fake APs | 0x08 | Alert + locate |
| 4 | Probe-flood reconnaissance | 0x04 | Alert + locate |
| 5 | Evil twin / rogue AP | 0x08 / 0x05 | Quarantine |
| 6 | Karma | 0x05 | Quarantine |

Detection of deauth / disassoc / beacon / probe is implemented in the sensor firmware. Evil-twin and karma detection (SSID extraction + cross-frame correlation) are stubbed with a documented approach — see the comments in the sensor sketches.

---

## Build & flash

Requires the **Arduino IDE** with the ESP8266 and ESP32 board packages, plus the **LiquidCrystal_I2C** library for the enforcer.

1. **Change the keys.** Open `firmware/common/protocol.h`, replace `KEY_MESH` and `KEY_UART` with your own 16 random bytes each, and re-copy the header into every sketch folder (each Arduino sketch includes its own local copy).
2. Flash `sensor_node_esp8266` to the ESP8266 (Node 1).
3. Flash `sensor_node_esp32s3` to the ESP32-S3 (Node 2 / coordinator).
4. Flash `arduino_enforcer` to the Arduino UNO.
5. Wire the rig per `hardware/` (coordinator TX → Arduino D2, common ground).

> These are reference firmware. ESP promiscuous-mode buffer layouts and the ESP-NOW receive-callback signature vary by core/SDK version — verify on your boards and tune the thresholds in each sketch to your environment.

## Security model (in brief)

- **Authentication + replay protection** on every enforcement-relevant message (SipHash-2-4 + per-sender counter), so a forged or replayed verdict/command is dropped.
- **Quorum ≥ 2**, so no single mistaken or compromised node can trigger or suppress enforcement.
- **Out-of-band enforcer** with no radio, unreachable over the medium it defends.

## Attack testing

The six attacks are demonstrated against **your own** test AP and client, in an isolated lab, using the established open-source tools (Spacehuhn deauther, ESP32 Marauder, mdk4, hostapd-mana). This repo documents the procedure in [`attack-testing/`](attack-testing/) but intentionally ships **no offensive attack code** — use the purpose-built tools. **Only ever test equipment you own and are authorised to test.**

## License

MIT — see [LICENSE](LICENSE).

## Credits

Rishikesh Walhekar · Gaurav More · Darpan Shah · Afnan Mulla — Guide: Prof. Alfiya Shahbad, CSE (AI & DS), Vishwakarma University, Pune.
