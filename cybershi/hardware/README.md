# Hardware — wiring and bill of materials

Drop the wiring schematic image here as `wiring-schematic.png` (the file exported
from the project). It documents the two domains below.

## Pin map (Arduino UNO enforcer)

| Arduino pin | Connects to | Purpose |
|---|---|---|
| A4 (SDA) | LCD SDA | I²C data to the 16×2 display |
| A5 (SCL) | LCD SCL | I²C clock |
| A0 | ACS712 OUT | Analog current reading of the victim's supply |
| D2 | Coordinator TX | Authenticated serial command in (SoftwareSerial RX) |
| D7 | Relay IN1 | Channel 1 — the victim's power |
| D8 | Buzzer (+) | Audible alarm |
| D9 | Green LED | Status: NORMAL |
| D10 | Red LED | Status: ALERT / quarantined |
| 5V / GND | Breadboard rails | Shared power and **common ground** |

- **Relay channel 1** switches the victim's 5 V feed (5 V → COM1, NC1 → device), so the device is powered when the relay is idle and cut when it trips.
- **ACS712** is wired in series on the victim's supply (IP+ / IP−); analog OUT → A0 (idles ≈ 2.5 V, Vcc/2).
- **One-way UART:** only coordinator TX → Arduino D2 plus a shared ground. The ESP32-S3 (3.3 V) TX reads as a valid HIGH on the UNO, so no level shifter is needed.

## Over-the-air boards (USB-powered, no signal wires)

| Device | Chip | Role |
|---|---|---|
| Attacker | ESP32 (Marauder) | Test harness only |
| Sensor Node 1 | ESP8266 | Promiscuous sniffer |
| Sensor Node 2 / Coordinator | ESP32-S3 Mini | Sniffer + coordinator (TX → Arduino D2) |
| Victim / protected device | ESP8266 | The device being defended and quarantined |

## Bill of materials (indicative, ≈ Rs. 3,500–4,000)

1× ESP32 dev board · 1× ESP32-S3 Mini · 2× ESP8266 (NodeMCU) · 1× Arduino UNO ·
1× 4-channel 5 V relay module · 1× 16×2 I²C LCD · 1× ACS712 current sensor ·
active buzzer · green/red/device LEDs · 220–330 Ω resistors · breadboard(s) ·
jumper wires · USB cables · three laptops to power the boards.
