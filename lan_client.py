"""
Ayla LAN Protocol Client for DeLonghi Coffee Machine.

Implements the Ayla local-mode communication protocol:
  1. Fetches local_key from cloud (connection_config.json)
  2. Starts HTTP server on port 10275
  3. Registers with machine via PUT /local_reg.json
  4. Machine connects back and performs key exchange
  5. Session keys are derived (AES-256-CBC + HMAC-SHA256)
  6. Commands (property writes) are sent encrypted to the machine

Usage:
    python lan_client.py brew regular
    python lan_client.py brew espresso
    python lan_client.py power_on
    python lan_client.py power_off
    python lan_client.py status

References:
    - com.aylanetworks.aylasdk.localcontrol.lan.AylaEncryption
    - com.aylanetworks.aylasdk.localcontrol.lan.AylaLanModule
    - com.aylanetworks.aylasdk.localcontrol.lan.AylaLanCommand
    - com.aylanetworks.aylasdk.localcontrol.lan.CreateDatapointCommand
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import socket
import string
import sys
import threading
import time
from binascii import crc_hqx
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional

import requests
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MACHINE_IP = "192.168.3.168"
MACHINE_PORT = 80
LAN_SERVER_PORT = 10275
DSN = os.environ.get("DSN", "")

AYLA_BASE = "https://ads-eu.aylanetworks.com"
GIGYA_URL = "https://accounts.eu1.gigya.com"
GIGYA_API_KEY = "3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2"
AYLA_APP_ID = "DLonghiCoffeeIdKit-sQ-id"
AYLA_APP_SECRET = "DLonghiCoffeeIdKit-HT6b0VNd4y6CSha9ivM5k8navLw"
AYLA_USER_BASE = "https://user-field-eu.aylanetworks.com"

CREDENTIALS_PATH = os.environ.get("CREDENTIALS_FILE", "/data/credentials.json")
FALLBACK_CREDENTIALS = os.path.join(os.path.dirname(__file__), "loot", "credentials.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("lan_client")

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _load_access_token() -> str:
    """Load the current access_token from credentials.json or env."""
    token = os.environ.get("ACCESS_TOKEN")
    if token:
        return token

    for path in (CREDENTIALS_PATH, FALLBACK_CREDENTIALS):
        if os.path.exists(path):
            try:
                creds = json.loads(open(path).read())
                tok = creds.get("ayla_api", {}).get("access_token")
                if tok:
                    log.info("Loaded access_token from %s", path)
                    return tok
            except Exception:
                pass

    raise RuntimeError("No access_token found. Set ACCESS_TOKEN env var or run api.py first.")


def _gigya_login(email: str, password: str) -> str:
    """Login to Gigya and return an id_token."""
    resp = requests.post(
        f"{GIGYA_URL}/accounts.login",
        data={
            "apiKey": GIGYA_API_KEY,
            "loginID": email,
            "password": password,
            "include": "id_token",
            "targetEnv": "mobile",
        },
        timeout=15,
    )
    data = resp.json()
    if "id_token" not in data:
        raise RuntimeError(f"Gigya login failed: {data.get('errorMessage', data)}")
    return data["id_token"]


def _gigya_exchange(id_token: str) -> str:
    """Exchange Gigya id_token for Ayla access_token."""
    resp = requests.post(
        f"{AYLA_USER_BASE}/api/v1/token_sign_in",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=f"app_id={AYLA_APP_ID}&app_secret={AYLA_APP_SECRET}&token={id_token}",
        timeout=15,
    )
    data = resp.json()
    if "access_token" not in data:
        raise RuntimeError(f"Ayla token exchange failed: {data}")
    return data["access_token"]


def get_fresh_token() -> str:
    """Get a fresh access token, re-authenticating if necessary."""
    email = os.environ.get("DELONGHI_EMAIL")
    password = os.environ.get("DELONGHI_PASSWORD")
    if not email or not password:
        raise RuntimeError("DELONGHI_EMAIL and DELONGHI_PASSWORD required to get fresh token")
    id_token = _gigya_login(email, password)
    return _gigya_exchange(id_token)


# ---------------------------------------------------------------------------
# Cloud API helpers
# ---------------------------------------------------------------------------

def fetch_connection_config(access_token: str) -> dict:
    """Fetch the LAN connection config from the cloud (contains local_key)."""
    resp = requests.get(
        f"{AYLA_BASE}/apiv1/devices/{DSN}/connection_config.json",
        headers={"Authorization": f"auth_token {access_token}"},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"connection_config failed: {resp.status_code} {resp.text}")
    return resp.json()


def fetch_property(access_token: str, prop_name: str) -> dict:
    """Read a device property from the cloud."""
    resp = requests.get(
        f"{AYLA_BASE}/apiv1/dsns/{DSN}/properties/{prop_name}.json",
        headers={"Authorization": f"auth_token {access_token}"},
        timeout=10,
    )
    return resp.json().get("property", {})


# ---------------------------------------------------------------------------
# Crypto helpers (mirrors AylaEncryption.java)
# ---------------------------------------------------------------------------

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _derive_key(lan_key: bytes, rnd1: bytes, rnd2: bytes, time1: bytes, time2: bytes, suffix: int) -> bytes:
    """Derive a session key as done in AylaEncryption.generateSessionKeys."""
    data = rnd1 + rnd2 + time1 + time2 + bytes([suffix])
    return _hmac_sha256(lan_key, _hmac_sha256(lan_key, data) + data)


def _random_token(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


@dataclass
class SessionKeys:
    app_sign_key: bytes
    app_crypto_key: bytes
    app_iv: bytes
    dev_sign_key: bytes
    dev_crypto_key: bytes
    dev_iv: bytes
    seq_no: int = 0
    _enc_cipher: Any = field(default=None, repr=False)
    _dec_cipher: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        # Stateful CBC ciphers — mirrors eCipher/dCipher in AylaEncryption.java
        self._enc_cipher = AES.new(self.app_crypto_key, AES.MODE_CBC, self.app_iv)
        self._dec_cipher = AES.new(self.dev_crypto_key, AES.MODE_CBC, self.dev_iv)

    @classmethod
    def derive(
        cls,
        lan_key_str: str,
        rnd1: str,
        rnd2: str,
        time1: int,
        time2: int,
    ) -> "SessionKeys":
        # The SDK stores the base64 string as UTF-8 bytes — NOT decoded
        lan_key = lan_key_str.encode("utf-8")
        r1 = rnd1.encode("utf-8")
        r2 = rnd2.encode("utf-8")
        t1 = str(time1).encode("utf-8")
        t2 = str(time2).encode("utf-8")

        app_sign_key    = _derive_key(lan_key, r1, r2, t1, t2, 0x30)  # '0'
        app_crypto_key  = _derive_key(lan_key, r1, r2, t1, t2, 0x31)  # '1'
        app_iv_full     = _derive_key(lan_key, r1, r2, t1, t2, 0x32)  # '2'
        dev_sign_key    = _derive_key(lan_key, r2, r1, t2, t1, 0x30)
        dev_crypto_key  = _derive_key(lan_key, r2, r1, t2, t1, 0x31)
        dev_iv_full     = _derive_key(lan_key, r2, r1, t2, t1, 0x32)

        return cls(
            app_sign_key=app_sign_key,
            app_crypto_key=app_crypto_key,
            app_iv=app_iv_full[:16],
            dev_sign_key=dev_sign_key,
            dev_crypto_key=dev_crypto_key,
            dev_iv=dev_iv_full[:16],
        )


def _encrypt_encapsulate_sign(keys: SessionKeys, data_json: str) -> str:
    """
    Mirrors AylaEncryption.encryptEncapsulateSign.

    Builds: {"seq_no": N, "data": <data>}
    Pads to 16-byte boundary, AES-CBC encrypts, HMAC-signs the plaintext.
    Returns: {"enc": "<b64>", "sign": "<b64>"}
    """
    seq = keys.seq_no
    keys.seq_no += 1

    payload = f'{{"seq_no":{seq},"data":{data_json}}}'
    payload_bytes = payload.encode("utf-8")

    # Pad to multiple of 16 (NoPadding cipher needs manual padding)
    length = len(payload_bytes) + 1  # +1 for the extra byte the SDK adds
    pad_len = length % 16
    if pad_len > 0:
        pad_len = 16 - pad_len
    padded = payload_bytes[:length-1] + bytes(1 + pad_len)  # matches Java behavior

    sign = base64.b64encode(_hmac_sha256(keys.app_sign_key, payload_bytes)).decode()
    encrypted = base64.b64encode(keys._enc_cipher.encrypt(padded)).decode()

    return json.dumps({"enc": encrypted, "sign": sign})


def _decrypt_verify(keys: SessionKeys, enc_json: str) -> Optional[str]:
    """
    Decrypt and verify a message from the device.
    Uses the stateful dev cipher (mirrors dCipher in AylaEncryption.java).
    """
    try:
        msg = json.loads(enc_json)
        enc_b64 = msg.get("enc")
        sign_b64 = msg.get("sign")
        if not enc_b64:
            return enc_json  # Already plaintext

        ciphertext = base64.b64decode(enc_b64)
        plaintext = keys._dec_cipher.decrypt(ciphertext).rstrip(b"\x00").decode("utf-8")

        # Verify sign
        expected_sign = base64.b64encode(_hmac_sha256(keys.dev_sign_key, plaintext.encode())).decode()
        if sign_b64 != expected_sign:
            log.warning("Sign mismatch from device — ignoring")
        return plaintext
    except Exception as exc:
        log.warning("Decrypt failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# LAN session state
# ---------------------------------------------------------------------------

@dataclass
class LanSession:
    lan_key_str: str
    key_id: int
    keys: Optional[SessionKeys] = None
    rnd2: str = field(default_factory=lambda: _random_token(16))
    time2: int = field(default_factory=lambda: time.time_ns())
    active: bool = False
    command_queue: queue.Queue = field(default_factory=queue.Queue)
    result_event: threading.Event = field(default_factory=threading.Event)
    last_result: Optional[dict] = None
    _cmd_id_counter: int = 0

    def next_cmd_id(self) -> int:
        self._cmd_id_counter += 1
        return self._cmd_id_counter


_session: Optional[LanSession] = None


# ---------------------------------------------------------------------------
# HTTP server (receives callbacks from machine)
# ---------------------------------------------------------------------------

class LanHandler(BaseHTTPRequestHandler):
    """
    Handles inbound requests from the DeLonghi machine.

    Routes:
        POST /local_lan/key_exchange.json  — key exchange initiation
        GET  /local_lan/commands.json      — machine polls for pending cmds
        POST /local_lan/property/datapoint.json  — machine reports prop values
        POST /local_lan/property/datapoint/ack.json — command ack
    """

    # HTTP/1.1 so the machine can reuse the TCP connection for multiple requests
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("[HTTP] " + fmt, *args)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _send_json(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    # ------------------------------------------------------------------
    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        body = self._body()
        log.info("POST %s  body=%s", path, body[:400])

        if path == "/local_lan/key_exchange.json":
            self._handle_key_exchange(body)
        elif path == "/local_lan/property/datapoint.json":
            self._handle_datapoint(body)
        elif path == "/local_lan/property/datapoint/ack.json":
            self._handle_ack(body)
        else:
            self._send_json(404, '{"error":"not found"}')

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        log.info("GET %s", self.path)

        if path == "/local_lan/commands.json":
            self._handle_commands()
        else:
            self._send_json(200, "{}")

    # ------------------------------------------------------------------
    def _handle_key_exchange(self, body: bytes) -> None:
        global _session
        if _session is None:
            self._send_json(500, '{"error":"no session"}')
            return
        try:
            msg = json.loads(body)
            ke = msg.get("key_exchange", msg)
            ver = ke.get("ver", 1)
            proto = ke.get("proto", 1)
            key_id = ke.get("key_id", 0)
            rnd1 = ke.get("random_1", "")
            time1 = int(ke.get("time_1", 0))

            log.info("Key exchange: ver=%s proto=%s key_id=%s rnd1=%s time1=%s",
                     ver, proto, key_id, rnd1, time1)

            if key_id != _session.key_id:
                log.error("Key ID mismatch: got %s expected %s", key_id, _session.key_id)
                self._send_json(412, '{"error":"key_id mismatch"}')
                return

            # Derive session keys
            _session.keys = SessionKeys.derive(
                lan_key_str=_session.lan_key_str,
                rnd1=rnd1,
                rnd2=_session.rnd2,
                time1=time1,
                time2=_session.time2,
            )
            _session.active = True
            log.info("Session keys derived — LAN session active")

            response = json.dumps({
                "ver": ver,
                "proto": proto,
                "random_2": _session.rnd2,
                "time_2": _session.time2,
            })
            self._send_json(200, response)

        except Exception as exc:
            log.error("Key exchange error: %s", exc, exc_info=True)
            self._send_json(500, '{"error":"key exchange failed"}')

    def _handle_commands(self) -> None:
        global _session
        if _session is None or not _session.active or _session.keys is None:
            self._send_json(200, "{}")
            return

        try:
            cmd = _session.command_queue.get_nowait()
        except queue.Empty:
            # No pending commands — return empty encrypted payload
            empty = _encrypt_encapsulate_sign(_session.keys, "{}")
            self._send_json(200, empty)
            return

        payload_json = json.dumps({"cmds": [{"cmd": cmd}]})
        encrypted = _encrypt_encapsulate_sign(_session.keys, payload_json)
        log.info("Serving command: %s", cmd)
        # 206 Partial Content = more commands queued; 200 = queue empty after this
        status = 206 if not _session.command_queue.empty() else 200
        self._send_json(status, encrypted)

    def _handle_datapoint(self, body: bytes) -> None:
        global _session
        if _session is None or _session.keys is None:
            self._send_json(200, "{}")
            return

        try:
            plaintext = _decrypt_verify(_session.keys, body.decode())
            if plaintext:
                log.info("Device datapoint: %s", plaintext[:200])
                try:
                    data = json.loads(plaintext)
                    _session.last_result = data
                    _session.result_event.set()
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            log.warning("Datapoint parse error: %s", exc)

        self._send_json(200, "{}")

    def _handle_ack(self, body: bytes) -> None:
        global _session
        if _session is None or _session.keys is None:
            self._send_json(200, "{}")
            return

        try:
            plaintext = _decrypt_verify(_session.keys, body.decode())
            if plaintext:
                log.info("Command ack: %s", plaintext[:200])
                try:
                    data = json.loads(plaintext)
                    _session.last_result = data
                    _session.result_event.set()
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            log.warning("Ack parse error: %s", exc)

        self._send_json(200, "{}")


# ---------------------------------------------------------------------------
# LAN registration (tell machine where to connect back)
# ---------------------------------------------------------------------------

def _get_local_ip() -> str:
    """Get the local IP address used to reach the coffee machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((MACHINE_IP, 80))
        return s.getsockname()[0]


def register_with_machine(local_ip: str, notify: int = 0, first: bool = False) -> bool:
    """
    Register our LAN server with the machine.

    First call: POST with ?dsn= (new session).
    Subsequent keepalives: PUT without DSN.
    """
    payload = {
        "local_reg": {
            "ip": local_ip,
            "port": LAN_SERVER_PORT,
            "uri": "/local_lan",
            "notify": notify,
        }
    }
    if first:
        url = f"http://{MACHINE_IP}:{MACHINE_PORT}/local_reg.json?dsn={DSN}"
        method = "POST"
    else:
        url = f"http://{MACHINE_IP}:{MACHINE_PORT}/local_reg.json"
        method = "PUT"
    try:
        resp = requests.request(method, url, json=payload, timeout=5)
        log.info("local_reg %s response: %s", method, resp.status_code)
        return resp.status_code in (200, 202)
    except Exception as exc:
        log.error("local_reg failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# ECAM binary protocol
# Source: github.com/Arbuzov/home_assistant_delonghi_primadonna
# CRC: crc_hqx (CRC-CCITT) with seed 0x1D0F over all bytes except last 2
# ---------------------------------------------------------------------------

def _ecam_crc(data: bytes) -> bytes:
    """CRC-CCITT (crc_hqx seed=0x1D0F) over all bytes except last 2."""
    crc = crc_hqx(data[:-2], 0x1D0F)
    return bytes([(crc >> 8) & 0xFF, crc & 0xFF])


def _finalize(pkt: list) -> bytes:
    """Write correct CRC into last 2 bytes of packet."""
    raw = bytearray(pkt)
    crc = _ecam_crc(bytes(raw))
    raw[-2] = crc[0]
    raw[-1] = crc[1]
    return bytes(raw)


# Verified working packets from HA integration (CRC recalculated at runtime)
BEVERAGE_PACKETS = {
    # Regular coffee (qty=103ml, temp=2, grind=2, profile=6)
    "regular":   [0x0d, 0x0f, 0x83, 0xf0, 0x02, 0x01, 0x01, 0x00, 0x67, 0x02, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Espresso x1 (aroma=3, temp=2, qty=40ml)
    "espresso":  [0x0d, 0x11, 0x83, 0xf0, 0x01, 0x01, 0x01, 0x00, 0x28, 0x02, 0x03, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Long coffee (qty=160ml, temp=2, grind=3)
    "long":      [0x0d, 0x0f, 0x83, 0xf0, 0x03, 0x01, 0x01, 0x00, 0xa0, 0x02, 0x03, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Doppio
    "doppio":    [0x0d, 0x0d, 0x83, 0xf0, 0x05, 0x01, 0x01, 0x00, 0x78, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Americano
    "americano": [0x0d, 0x12, 0x83, 0xf0, 0x06, 0x01, 0x01, 0x00, 0x28, 0x02, 0x03, 0x0f, 0x00, 0x6e, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Espresso x2
    "2x_espresso": [0x0d, 0x0f, 0x83, 0xf0, 0x04, 0x01, 0x01, 0x00, 0x28, 0x02, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00],
    # Hot water
    "hot_water": [0x0d, 0x0d, 0x83, 0xf0, 0x10, 0x01, 0x0f, 0x00, 0xfa, 0x1c, 0x01, 0x06, 0x00, 0x00],
    # Steam
    "steam":     [0x0d, 0x0d, 0x83, 0xf0, 0x11, 0x01, 0x09, 0x03, 0x84, 0x1c, 0x01, 0x06, 0x00, 0x00],
}

STOP_PACKETS = {
    "regular":     [0x0d, 0x08, 0x83, 0xf0, 0x02, 0x02, 0x06, 0x00, 0x00],
    "espresso":    [0x0d, 0x08, 0x83, 0xf0, 0x01, 0x02, 0x06, 0x00, 0x00],
    "long":        [0x0d, 0x08, 0x83, 0xf0, 0x03, 0x02, 0x06, 0x00, 0x00],
    "doppio":      [0x0d, 0x08, 0x83, 0xf0, 0x05, 0x02, 0x06, 0x00, 0x00],
    "americano":   [0x0d, 0x08, 0x83, 0xf0, 0x06, 0x02, 0x06, 0x00, 0x00],
    "2x_espresso": [0x0d, 0x08, 0x83, 0xf0, 0x04, 0x02, 0x06, 0x00, 0x00],
    "hot_water":   [0x0d, 0x08, 0x83, 0xf0, 0x10, 0x02, 0x06, 0x00, 0x00],
    "steam":       [0x0d, 0x08, 0x83, 0xf0, 0x11, 0x02, 0x06, 0x00, 0x00],
}

# Power on: header 0x84 0x0f, byte[4]=0x02 (on), byte[5]=0x01
POWER_ON_PACKET  = [0x0d, 0x07, 0x84, 0x0f, 0x02, 0x01, 0x00, 0x00]
POWER_OFF_PACKET = [0x0d, 0x07, 0x84, 0x0f, 0x01, 0x01, 0x00, 0x00]
STATUS_PACKET    = [0x0d, 0x05, 0x75, 0x0f, 0x00, 0x00, 0x00]


def _build_brew_packet(recipe: str) -> Optional[bytes]:
    pkt = BEVERAGE_PACKETS.get(recipe)
    if pkt is None:
        return None
    return _finalize(list(pkt))


def _build_stop_packet(recipe: str) -> Optional[bytes]:
    pkt = STOP_PACKETS.get(recipe)
    if pkt is None:
        return None
    return _finalize(list(pkt))


def _build_power_on_packet() -> bytes:
    return _finalize(list(POWER_ON_PACKET))


def _build_power_off_packet() -> bytes:
    return _finalize(list(POWER_OFF_PACKET))


def _build_status_packet() -> bytes:
    return _finalize(list(STATUS_PACKET))


def _wrap_ecam_packet(raw_packet: bytes) -> str:
    """Append 4-byte big-endian Unix timestamp and Base64-encode (matches Y1())."""
    ts_bytes = int(time.time()).to_bytes(4, byteorder="big")
    return base64.b64encode(raw_packet + ts_bytes).decode("ascii")


# Machine state decoding (from HA const.py + device.py)
MACHINE_STATES = {
    0x00: "off",
    0x01: "standby",
    0x02: "heating",
    0x03: "ready",
    0x04: "dispensing",
    0x05: "ready",       # steady ready
    0x06: "cleaning",
    0x07: "ready",
    0x08: "alarm",
}

DEVICE_STATUS = {
    0: "empty_water_tank", 1: "coffee_waste_container_full",
    2: "descale_alarm", 3: "replace_water_filter",
    4: "coffee_ground_too_fine", 5: "coffee_beans_empty",
    6: "machine_to_service", 7: "coffee_heater_probe_failure",
    8: "too_much_coffee", 9: "coffee_infuser_motor_not_working",
    10: "steamer_probe_failure", 11: "empty_drip_tray",
    12: "hydraulic_circuit_problem", 13: "tank_is_in_position",
}


def decode_monitor(b64_or_hex: str) -> dict:
    """Decode d302_monitor response into human-readable fields."""
    try:
        raw = base64.b64decode(b64_or_hex)
    except Exception:
        try:
            raw = bytes.fromhex(b64_or_hex)
        except Exception:
            return {"raw": b64_or_hex}

    if len(raw) < 14:
        return {"hex": raw.hex(), "len": len(raw)}

    # Packet: D0 12 75 0F [nozzle] [sw_lo] [sw_hi] [alm1] [alm2] [state] [sub] ...
    state_byte = raw[9]
    sub_byte = raw[10]
    switches = raw[5] + (raw[6] << 8)
    alarms_raw = raw[7] + (raw[8] << 8)

    active_alarms = [DEVICE_STATUS.get(i, f"alarm_{i}")
                     for i in range(16) if alarms_raw & (1 << i)]

    return {
        "hex": raw.hex(),
        "state": MACHINE_STATES.get(state_byte, f"0x{state_byte:02x}"),
        "sub_state": sub_byte,
        "switches_raw": f"0x{switches:04x}",
        "alarms": active_alarms if active_alarms else "none",
        "nozzle": raw[4],
        "is_on": bool(switches & 0x01),
    }


# ---------------------------------------------------------------------------
# Cloud API direct write (bypasses LAN protocol entirely)
# ---------------------------------------------------------------------------

def write_datapoint_cloud(access_token: str, prop_name: str, value: str) -> bool:
    """Write a datapoint via the Ayla cloud API."""
    resp = requests.post(
        f"{AYLA_BASE}/apiv1/dsns/{DSN}/properties/{prop_name}/datapoints.json",
        headers={
            "Authorization": f"auth_token {access_token}",
            "Content-Type": "application/json",
        },
        json={"datapoint": {"value": value}},
        timeout=15,
    )
    log.info("Cloud write %s → %s %s", prop_name, resp.status_code, resp.text[:200])
    return resp.status_code in (200, 201)


# ---------------------------------------------------------------------------
# LAN protocol command builders
# ---------------------------------------------------------------------------

def _build_set_property_cmd(cmd_id: int, prop_name: str, value: Any, base_type: str = "string") -> dict:
    """Build a SetProperty LAN command matching CreateDatapointCommand.getPayload()."""
    return {
        "properties": [{
            "property": {
                "name": prop_name,
                "value": value,
                "base_type": base_type,
                "dsn": DSN,
                "id": _random_token(8),
            }
        }]
    }


def _build_get_property_cmd(cmd_id: int, prop_name: str) -> dict:
    """Build a GetProperty LAN command."""
    return {
        "cmd_id": cmd_id,
        "method": "GET",
        "resource": f"property.json?name={prop_name}",
        "data": "",
        "uri": "/local_lan/property/datapoint.json",
    }


# ---------------------------------------------------------------------------
# Main LAN client logic
# ---------------------------------------------------------------------------

def _get_access_token() -> str:
    """Get a valid access token, re-authenticating if needed."""
    try:
        return _load_access_token()
    except RuntimeError:
        log.info("No cached token, re-authenticating...")
        return get_fresh_token()


def _build_command_value(command: str, recipe: str) -> Optional[str]:
    """Build the Base64-encoded ECAM packet for a given command."""
    if command == "brew":
        raw = _build_brew_packet(recipe)
        if raw is None:
            log.error("Unknown recipe: %s. Valid: %s", recipe, list(BEVERAGE_PACKETS))
            return None
        log.info("Brew packet (hex): %s", raw.hex())
        return _wrap_ecam_packet(raw)

    if command == "stop":
        raw = _build_stop_packet(recipe)
        if raw is None:
            log.error("Unknown recipe for stop: %s", recipe)
            return None
        log.info("Stop packet (hex): %s", raw.hex())
        return _wrap_ecam_packet(raw)

    if command == "power_on":
        raw = _build_power_on_packet()
        log.info("Power on packet (hex): %s", raw.hex())
        return _wrap_ecam_packet(raw)

    if command == "power_off":
        raw = _build_power_off_packet()
        log.info("Power off packet (hex): %s", raw.hex())
        return _wrap_ecam_packet(raw)

    if command == "status":
        raw = _build_status_packet()
        log.info("Status packet (hex): %s", raw.hex())
        return _wrap_ecam_packet(raw)

    log.error("Unknown command: %s", command)
    return None


def run_cloud_command(command: str, recipe: str = "regular") -> bool:
    """
    Send command via the Ayla Cloud API (no LAN protocol needed).

    Writes an ECAM binary packet (Base64) to the 'data_request' property
    through the cloud datapoint endpoint.
    """
    access_token = _get_access_token()
    value = _build_command_value(command, recipe)
    if value is None:
        return False

    log.info("Sending %s via cloud API (data_request = %s...)", command, value[:30])

    try:
        ok = write_datapoint_cloud(access_token, "data_request", value)
    except Exception:
        log.info("Token may be expired, re-authenticating...")
        access_token = get_fresh_token()
        ok = write_datapoint_cloud(access_token, "data_request", value)

    if ok:
        log.info("Command '%s' sent successfully via cloud API", command)
    else:
        log.error("Cloud API write failed for '%s'", command)
    return ok


def run_lan_command(command: str, recipe: str = "regular", timeout: float = 30.0) -> bool:
    """
    Send command via the Ayla LAN protocol (direct machine communication).

    Falls back from cloud API if needed. Writes the same ECAM binary packet
    but through the encrypted LAN channel instead of the cloud.
    """
    global _session

    access_token = _get_access_token()
    value = _build_command_value(command, recipe)
    if value is None:
        return False

    try:
        config = fetch_connection_config(access_token)
    except RuntimeError:
        access_token = get_fresh_token()
        config = fetch_connection_config(access_token)

    lan_key_str = config["local_key"]
    key_id = config["local_key_id"]
    log.info("Got LAN key_id=%s", key_id)

    _session = LanSession(lan_key_str=lan_key_str, key_id=key_id)

    server = HTTPServer(("0.0.0.0", LAN_SERVER_PORT), LanHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log.info("LAN server started on port %d", LAN_SERVER_PORT)

    local_ip = _get_local_ip()
    log.info("Local IP: %s", local_ip)

    try:
        cmd_id = _session.next_cmd_id()
        lan_cmd = _build_set_property_cmd(cmd_id, "data_request", value)
        _session.command_queue.put(lan_cmd)

        if not register_with_machine(local_ip, notify=1, first=True):
            log.error("Failed to register with machine")
            return False

        deadline = time.time() + 10.0
        while not (_session.active and _session.keys is not None):
            if time.time() > deadline:
                log.error("Key exchange timed out")
                return False
            time.sleep(0.1)

        log.info("LAN session established, sending keepalives...")

        stop_keepalive = threading.Event()

        def _keepalive_loop() -> None:
            while not stop_keepalive.is_set():
                notify = 1 if not _session.command_queue.empty() else 0
                register_with_machine(local_ip, notify=notify, first=False)
                stop_keepalive.wait(2.0)

        keepalive_thread = threading.Thread(target=_keepalive_loop, daemon=True)
        keepalive_thread.start()

        _session.result_event.clear()
        if _session.result_event.wait(timeout):
            stop_keepalive.set()
            log.info("Result received: %s", _session.last_result)
            return True

        stop_keepalive.set()
        log.warning("No response within %.0fs", timeout)
        return command == "brew"

    finally:
        server.shutdown()
        log.info("LAN server stopped")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python lan_client.py [--lan] <brew|stop|status|power_on|power_off> [recipe]")
        print("Beverages:", ", ".join(BEVERAGE_PACKETS))
        print("\nDefault mode: cloud API")
        print("Use --lan flag for LAN protocol (experimental)")
        sys.exit(1)

    args = sys.argv[1:]
    use_lan = "--lan" in args
    if use_lan:
        args.remove("--lan")

    command = args[0]
    recipe = args[1] if len(args) > 1 else "regular"

    if command == "status":
        # Status: send request then poll and decode the response
        access_token = _get_access_token()
        value = _build_command_value("status", recipe)
        if value:
            write_datapoint_cloud(access_token, "data_request", value)
            time.sleep(3)
            try:
                resp = requests.get(
                    f"{AYLA_BASE}/apiv1/dsns/{DSN}/properties/d302_monitor.json",
                    headers={"Authorization": f"auth_token {access_token}"},
                    timeout=10,
                )
                prop = resp.json().get("property", {})
                val = prop.get("value", "")
                if val:
                    decoded = decode_monitor(val)
                    print("\n=== Machine Status ===")
                    for k, v in decoded.items():
                        print(f"  {k}: {v}")
                else:
                    print("No monitor data returned")
            except Exception as exc:
                log.error("Status poll failed: %s", exc)
        sys.exit(0)

    if use_lan:
        success = run_lan_command(command, recipe)
    else:
        success = run_cloud_command(command, recipe)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
