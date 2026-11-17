# Shared firmware headers

- **`siphash.h`** — SipHash-2-4 keyed MAC, used to authenticate and replay-protect
  both the ESP-NOW verdicts and the coordinator → Arduino command.
- **`protocol.h`** — the `Verdict` and `Command` message formats, the attack-class
  enum, the pre-shared keys (`KEY_MESH`, `KEY_UART` — **change these**), and the
  sign/verify helpers.

Arduino compiles each sketch from its own folder, so these two headers are
**copied into every sketch directory** (`sensor_node_esp8266/`,
`sensor_node_esp32s3/`, `arduino_enforcer/`). This folder holds the canonical
copies — if you edit a header here, copy it back into each sketch folder:

```bash
for d in sensor_node_esp8266 sensor_node_esp32s3 arduino_enforcer; do
  cp common/siphash.h common/protocol.h "firmware/$d/"
done
```
