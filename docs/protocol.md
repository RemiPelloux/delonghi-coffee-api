# ECAM Protocol Reference

Binary protocol used by DeLonghi machines (ECAM series).
All commands are written to the `data_request` Ayla property as Base64-encoded packets.

---

## Packet Structure

```
[HEADER] [LEN] [CMD_HI] [CMD_LO] [PAYLOAD...] [CRC_HI] [CRC_LO]
+ 4 bytes Unix timestamp appended before Base64 encoding
```

| Field | Size | Value | Notes |
|-------|------|-------|-------|
| HEADER | 1 byte | `0x0D` | Always |
| LEN | 1 byte | varies | Total packet byte count |
| CMD | 2 bytes | see below | Command type |
| PAYLOAD | varies | — | Command-specific |
| CRC | 2 bytes | computed | CRC-CCITT, seed `0x1D0F` |
| TIMESTAMP | 4 bytes | Unix epoch | Big-endian, appended after CRC |

---

## Command Types

| CMD bytes | Purpose |
|-----------|---------|
| `0x83 0xF0` | Beverage dispensing |
| `0x84 0x0F` | Power control |
| `0x75 0x0F` | Status request |

---

## Beverage Packet Layout (CMD = `0x83 0xF0`)

```
0x0D [LEN] 0x83 0xF0 [BEV_ID] [OP] [QTY] [VOL_HI] [VOL_LO] [GRIND] [...] 0x06 [CRC_HI] [CRC_LO]
```

| Field | Notes |
|-------|-------|
| BEV_ID | 1=espresso, 2=regular, 3=long, 4=2x_espresso, 5=doppio, 6=americano, 16=hot_water, 17=steam |
| OP | `0x01` = START, `0x02` = STOP |
| QTY | Quantity (0x01 for single) |
| VOL | Volume in ml, big-endian (0x0067 = 103ml) |
| GRIND | Grind size settings |

---

## Verified Packet Templates

Last 2 bytes are CRC placeholders (`0x00 0x00`) — always recalculate before sending.

| Beverage | Hex (without timestamp) |
|----------|------------------------|
| espresso | `0d 11 83 f0 01 01 01 00 28 02 03 08 00 00 00 06 00 00` |
| regular | `0d 0f 83 f0 02 01 01 00 67 02 02 00 00 06 00 00` |
| long | `0d 0f 83 f0 03 01 01 00 a0 02 03 00 00 06 00 00` |
| 2x_espresso | `0d 0f 83 f0 04 01 01 00 28 02 02 00 00 06 00 00` |
| doppio | `0d 0d 83 f0 05 01 01 00 78 00 00 06 00 00` |
| americano | `0d 12 83 f0 06 01 01 00 28 02 03 0f 00 6e 00 00 06 00 00` |
| hot_water | `0d 0d 83 f0 10 01 0f 00 fa 1c 01 06 00 00` |
| steam | `0d 0d 83 f0 11 01 09 03 84 1c 01 06 00 00` |

**Stop packets** — same beverage ID, OP = `0x02`:
```
0d 08 83 f0 [BEV_ID] 02 06 00 00
```

**Power packets:**
```
Power ON  → 0d 07 84 0f 02 01 00 00
Power OFF → 0d 07 84 0f 01 01 00 00
Status    → 0d 05 75 0f 00 00 00
```

---

## CRC Algorithm

CRC-CCITT, applied over all bytes **except the last two** (the placeholder bytes).

```python
from binascii import crc_hqx

def finalize(pkt: list[int]) -> bytes:
    raw = bytearray(pkt)
    crc = crc_hqx(bytes(raw[:-2]), 0x1D0F)  # seed = 0x1D0F
    raw[-2] = (crc >> 8) & 0xFF
    raw[-1] = crc & 0xFF
    return bytes(raw)
```

---

## Timestamp Wrapping

After CRC, append a 4-byte big-endian Unix timestamp, then Base64-encode the whole packet.
The machine rejects packets with stale timestamps (> a few seconds old).

```python
import base64, time

def wrap(raw: bytes) -> str:
    return base64.b64encode(raw + int(time.time()).to_bytes(4, "big")).decode()
```

---

## d302_monitor Decoding

Machine state is read from the `d302_monitor` property (Base64-encoded binary).

| Byte offset | Content |
|-------------|---------|
| 4 | Nozzle position |
| 5-6 | Switch bitmap (bit 0 = machine is on) |
| 7-8, 12-13 | Alarm bitmap (32-bit, see below) |
| 9 | Machine state code |
| 10 | Sub-state |

**State codes (byte 9):**

| Code | State |
|------|-------|
| `0x00` | Off |
| `0x01` | Standby |
| `0x02` | Heating |
| `0x03` | Ready |
| `0x04` | Dispensing |
| `0x06` | Cleaning |
| `0x08` | Alarm |

**Alarm bits:**

| Bit | Alarm |
|-----|-------|
| 0 | Empty water tank |
| 1 | Coffee waste full |
| 2 | Descale required |
| 3 | Replace water filter |
| 5 | Coffee beans empty |
| 11 | Empty drip tray |
| 12 | Hydraulic circuit problem |

---

## Sources

- Extracted from `coffee-link.apk` via `apktool` + `jadx`
- Key files: `C2442d.java` (packet builder), `DeLonghiWifiConnectService.java` (timestamp + send)
- Cross-validated with [home_assistant_delonghi_primadonna](https://github.com/Arbuzov/home_assistant_delonghi_primadonna)
