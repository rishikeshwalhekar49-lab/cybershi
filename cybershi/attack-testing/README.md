# Attack testing (authorised lab use only)

To prove the detector works, each attack is launched against **your own** test AP
and throwaway client, in an **isolated lab**, using established open-source tools.
This folder contains **no offensive code** — the attacks already have mature,
purpose-built implementations that are the correct, reliable way to test a WIDS.
You *flash/run* them; you do not re-implement them.

> ⚠️ **Only ever test equipment you own and are authorised to test.** Target a
> specific BSSID (never broadcast), lock everything to channel 6, isolate from
> other networks, and keep written authorisation. Unauthorised deauthentication
> or interference is illegal (in India, IT Act 2000, §43 & §66).

## Tools

| Tool | Covers | Needs |
|---|---|---|
| [Spacehuhn esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther) | deauth · disassoc · beacon · probe | the ESP8266 attacker board |
| [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) | same set on ESP32 | the ESP32 attacker board |
| [mdk4](https://github.com/aircrack-ng/mdk4) | clean, separate floods | a Linux laptop + monitor-mode adapter |
| [hostapd-mana](https://github.com/sensepost/hostapd-mana) | karma / evil twin | a Linux laptop + monitor-mode adapter |

## Procedure (summary)

1. **Deauth / disassoc** — in the Spacehuhn panel (`192.168.4.1`): Scan → pick *your* AP → Attacks → Deauth → Start. For a clean, separate disassoc flood: `mdk4 <iface> d`.
2. **Beacon flood** — Spacehuhn → SSIDs (add fake names) → Beacon → Start.
3. **Probe flood** — `mdk4 <iface> p` on channel 6, or the deauther's probe mode.
4. **Evil twin** — bring up a second AP (phone hotspot / spare router / ESP SoftAP) with your *exact* SSID on channel 6.
5. **Karma** — `hostapd-mana` in karma mode on channel 6.

## Confirm each attack fires (Wireshark)

Capture on channel 6 and filter by sub-type before blaming the detector:

| Attack | Wireshark filter |
|---|---|
| Deauthentication | `wlan.fc.type_subtype == 0x0c` |
| Disassociation | `wlan.fc.type_subtype == 0x0a` |
| Beacon flood | `wlan.fc.type_subtype == 0x08` |
| Probe request | `wlan.fc.type_subtype == 0x04` |
| Karma / probe response | `wlan.fc.type_subtype == 0x05` |
| Evil twin | `0x08` with two BSSIDs advertising one SSID |
