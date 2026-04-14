# Reverse Engineering a DeLonghi Coffee Machine — From APK to Local REST API

> How I decompiled an Android app, intercepted its traffic, reversed a proprietary binary protocol, and built a local API to control my coffee machine with an AI assistant.

---

## Table of Contents

1. [The Goal](#1-the-goal)
2. [The Problem — Everything Goes Through the Cloud](#2-the-problem--everything-goes-through-the-cloud)
3. [Step 1 — Decompiling the APK](#3-step-1--decompiling-the-apk)
4. [Step 2 — Intercepting the Traffic](#4-step-2--intercepting-the-traffic)
5. [Step 3 — Understanding the ECAM Binary Protocol](#5-step-3--understanding-the-ecam-binary-protocol)
6. [Step 4 — The CRC Mystery](#6-step-4--the-crc-mystery)
7. [Step 5 — The Missing Timestamp](#7-step-5--the-missing-timestamp)
8. [Step 6 — Building Packets from Scratch](#8-step-6--building-packets-from-scratch)
9. [Everything That Did Not Work](#9-everything-that-did-not-work)
10. [The Final Architecture](#10-the-final-architecture)
11. [Lessons Learned](#11-lessons-learned)

---

## 1. The Goal

I have a DeLonghi Dinamica Plus coffee machine. It is connected to Wi-Fi, it has an app, and it works fine. But I wanted something specific: my local AI assistant should be able to make me a coffee by just asking it. No cloud dependency. No phone. Just an HTTP call.

The plan seemed simple. Find the API, wrap it in a small REST server, point my AI at it. Two weeks later I had decompiled an APK, intercepted HTTPS traffic, reversed a proprietary binary protocol, and written a CRC function from scratch. Here is everything that happened.

---

## 2. The Problem — Everything Goes Through the Cloud

The first thing I checked was whether the machine exposed anything locally. It has a Wi-Fi module (an ESP32 from Espressif, visible in the MAC address vendor `54:43:b2`). Port scan: only port 80 open, returning 404 on every route. The machine talks to the Ayla Networks IoT cloud, not directly to the phone.

The full authentication chain:

```
DeLonghi app
    → Gigya (SAP) SSO  [accounts.eu1.gigya.com]
        → exchange id_token for Ayla token
            → Ayla Networks cloud  [ads-eu.aylanetworks.com]
                → machine (via LAN polling or cloud push)
```

Every command goes through `ads-eu.aylanetworks.com`. The tokens rotate every 24 hours. There is no documented public API.

---

## 3. Step 1 — Decompiling the APK

I pulled the APK from the Play Store (`coffee-link.apk`) and decompiled it with two tools:

- **apktool** — extracts the raw Smali bytecode and resources
- **jadx** — decompiles Smali back into readable Java

The codebase is obfuscated. Class names are things like `C2442d`, `j6.z`, `C0983o`. But the logic is all there.

The most important files I found:

| File | What it contains |
|------|-----------------|
| `AylaEncryption.java` | AES-256-CBC + HMAC-SHA256 for the LAN mode |
| `AylaLanModule.java` | Local network registration and command dispatch |
| `DeLonghiWifiConnectService.java` | The method that actually sends commands to the machine |
| `C2442d.java` | The ECAM binary packet builder — every beverage, every command |
| `EnumC2612a.java` | Beverage ID enum (espresso=1, regular=2, long=3…) |

The most critical discovery was in `DeLonghiWifiConnectService.java`, in a method called `Y1()`:

```java
private String Y1(byte[] bArr) {
    byte[] bArr2 = new byte[bArr.length + 4];
    System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
    int currentTimeSeconds = (int) (System.currentTimeMillis() / 1000);
    bArr2[bArr.length]     = (byte) ((currentTimeSeconds >> 24) & 0xFF);
    bArr2[bArr.length + 1] = (byte) ((currentTimeSeconds >> 16) & 0xFF);
    bArr2[bArr.length + 2] = (byte) ((currentTimeSeconds >>  8) & 0xFF);
    bArr2[bArr.length + 3] = (byte) (currentTimeSeconds & 0xFF);
    return Base64.encodeToString(bArr2, 2);
}
```

This method takes the raw binary command, **appends the current Unix timestamp as 4 bytes big-endian**, then Base64-encodes the result. This is the format expected by the `data_request` Ayla property.

Without this timestamp the machine silently ignores every command. This was one of the hardest bugs to find.

---

## 4. Step 2 — Intercepting the Traffic

To understand what properties the app reads and writes, I set up `mitmproxy` as an HTTPS proxy on my Mac, installed the mitmproxy CA certificate on my Android phone, and captured a full session while making a coffee.

The key findings from the traffic:

**Authentication flow:**
```
POST https://accounts.eu1.gigya.com/accounts.login
  → returns id_token

POST https://user-field-eu.aylanetworks.com/api/v1/token_sign_in
  → returns access_token + refresh_token (valid 24h)
```

**Sending a brew command:**
```
POST https://ads-eu.aylanetworks.com/apiv1/dsns/{DSN}/properties/data_request/datapoints.json
Authorization: auth_token {access_token}
{"datapoint": {"value": "DQ+D8AIBAQBnAgIAAAZ3/2neJ3s="}}
```

**Reading machine state:**
```
GET https://ads-eu.aylanetworks.com/apiv1/dsns/{DSN}/properties/d302_monitor.json
  → {"property": {"value": "0BJ1DwAAAAAHAAAAAAAA1qNp3iWg", "data_updated_at": "..."}}
```

Two properties matter: `data_request` (write commands) and `d302_monitor` (read machine state). Everything else is counters, recipes, and settings.

---

## 5. Step 3 — Understanding the ECAM Binary Protocol

The value written to `data_request` is Base64-encoded binary. Decoding the example above:

```
DQ+D8AIBAQBnAgIAAAZ3/2neJ3s=
→ hex: 0d 0f 83 f0 02 01 01 00 67 02 02 00 00 06 77 ff [4-byte timestamp]
```

Cross-referencing with `C2442d.java`, the packet structure is:

```
Byte 0:    0x0D          — packet header (always)
Byte 1:    0x0F          — packet length (15 bytes total)
Bytes 2-3: 0x83 0xF0     — command type: beverage/dispense
Byte 4:    0x02          — beverage ID (2 = regular coffee)
Byte 5:    0x01          — operation: START (0x01) or STOP (0x02)
Byte 6:    0x01          — quantity
Bytes 7-8: 0x00 0x67     — volume in ml (103ml)
Bytes 9-10: 0x02 0x02    — grind settings
...
Last 2:    CRC bytes      — checksum
+ 4 bytes: Unix timestamp  — appended by Y1() before Base64
```

Command types found in `C2442d.java`:

| Bytes 2-3 | Purpose |
|-----------|---------|
| `0x83 0xF0` | Beverage dispensing |
| `0x84 0x0F` | Power control |
| `0x75 0x0F` | Status request |

---

## 6. Step 4 — The CRC Mystery

The last two bytes of every packet are a checksum. The Java code in `C2442d.java` had this:

```java
int crc = 0x1D0F;
for (byte b : data) {
    crc ^= (b << 8);
    for (int i = 0; i < 8; i++) {
        if ((crc & 0x8000) != 0) crc = (crc << 1) ^ 0x1021;
        else crc <<= 1;
    }
}
```

This is CRC-CCITT (polynomial `0x1021`, initial value `0x1D0F`). I spent three hours writing a custom implementation before realizing Python's standard library has it:

```python
from binascii import crc_hqx

crc = crc_hqx(data[:-2], 0x1D0F)
```

That is all it is. `crc_hqx` is CRC-CCITT with a configurable seed. One line.

Validation came from the [home_assistant_delonghi_primadonna](https://github.com/Arbuzov/home_assistant_delonghi_primadonna) project, which independently implemented the same algorithm and whose packets matched the traffic I had captured.

---

## 7. Step 5 — The Missing Timestamp

With the correct CRC working, my first test commands were silently ignored by the machine. The API returned `201 Created` every time, but nothing happened.

Going back to `DeLonghiWifiConnectService.java` and re-reading `Y1()` carefully: the method appends a 4-byte big-endian Unix timestamp to the raw packet **before** Base64-encoding. This is how the machine detects replayed or stale commands — it rejects packets with a timestamp more than a few seconds in the past.

Without the timestamp the machine receives the command, sees an invalid trailing sequence, and drops it.

```python
def ecam_wrap(raw_packet: bytes) -> str:
    timestamp = int(time.time()).to_bytes(4, byteorder="big")
    return base64.b64encode(raw_packet + timestamp).decode()
```

After adding this, the first real brew command worked immediately.

---

## 8. Step 6 — Building Packets from Scratch

With CRC and timestamp working, I built a packet for a regular coffee:

```python
from binascii import crc_hqx
import base64, time

def finalize(pkt: list[int]) -> bytes:
    raw = bytearray(pkt)
    crc = crc_hqx(bytes(raw[:-2]), 0x1D0F)
    raw[-2] = (crc >> 8) & 0xFF
    raw[-1] = crc & 0xFF
    return bytes(raw)

def wrap(raw: bytes) -> str:
    return base64.b64encode(raw + int(time.time()).to_bytes(4, "big")).decode()

# Regular coffee — beverage ID 2, 103ml, standard grind
regular = [0x0d, 0x0f, 0x83, 0xf0, 0x02, 0x01, 0x01, 0x00,
           0x67, 0x02, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00]
payload = wrap(finalize(regular))
# → "DQ+D8AIBAQBnAgIAAAZ3/2neJ3s="
```

This matches exactly the packet captured from the real app. Sending it to `data_request` via the Ayla cloud API makes the machine brew immediately.

---

## 9. Everything That Did Not Work

**Writing `d000_on_off_eco`** — this property exists but the machine echoes back the write without acting on it. It is not the right way to control power.

**Re-writing recipe properties** (`d001_rec_espresso`, etc.) — I thought writing the current recipe value back to its property would trigger a brew. It does not. The machine only responds to `data_request`.

**Passive `tcpdump` on Wi-Fi** — on a standard Wi-Fi network, unicast traffic between two client devices (the phone and the machine) does not pass through the Mac's network interface. You see the packets only if you are the access point or performing a MITM. The traffic capture only worked via `mitmproxy` on the phone, not via passive sniffing.

**Standard CRC-16** — the initial guess was CRC-16/IBM (seed `0xFFFF`, polynomial `0x8005`). Wrong. The algorithm is CRC-CCITT with a non-standard seed `0x1D0F`. The seed is what makes it unusual — most CRC-CCITT implementations default to `0xFFFF`.

**No timestamp** — commands with a correctly-computed CRC but no appended timestamp are silently dropped by the machine. No error, no response, nothing.

---

## 10. The Final Architecture

```
┌─────────────┐      HTTP POST /brew       ┌──────────────────────┐
│  AI / Client│ ─────────────────────────▶ │  FastAPI  (port 8000)│
└─────────────┘                            └──────────┬───────────┘
                                                      │
                                          Build ECAM packet
                                          Apply CRC-CCITT
                                          Append timestamp
                                          Base64 encode
                                                      │
                                                      ▼
                                           ┌──────────────────┐
                                           │  Ayla Cloud API  │
                                           │ data_request prop│
                                           └────────┬─────────┘
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │  DeLonghi machine│
                                           │  192.168.3.168   │
                                           └──────────────────┘
```

The API runs in Docker on a Raspberry Pi on the local network. Token refresh happens automatically — if the 24h Ayla token expires, the server re-authenticates via Gigya using stored credentials without any downtime.

---

## 11. Lessons Learned

**IoT devices are opaque, not secure.** The ECAM protocol has no encryption, no authentication, and no per-user signing. The only replay protection is the Unix timestamp, which means any attacker on the same network who can see the `data_request` value can replay commands by updating the timestamp. The cloud layer (Ayla) provides the authentication; the machine itself trusts anything that arrives via `data_request`.

**Decompiled Java is remarkably readable.** Despite the obfuscation, the core logic in `C2442d.java` and `DeLonghiWifiConnectService.java` was straightforward to read once I knew what I was looking for. The method names were garbage but the byte arrays and constants were intact.

**The timestamp is the hardest bug to diagnose.** Silent drops with no error messages are the worst failure mode. If the machine had returned an error code I would have found the timestamp issue in minutes instead of days.

**Search for existing work first.** The Home Assistant community had already mapped this protocol. Two hours of research before starting would have saved days of work. The CRC seed, the packet structures, and the timestamp format were all documented in the HA integration.

**`crc_hqx` is Python's hidden gem.** CRC-CCITT with a configurable seed is built into the standard library. Nobody knows about it because it is buried in `binascii` next to `crc32` and `hexlify`.
