"""
DeLonghi Coffee Machine — Local REST API.

Controls your DeLonghi via ECAM binary protocol over the Ayla Networks cloud.
Reverse-engineered from the official app + verified against:
  https://github.com/Arbuzov/home_assistant_delonghi_primadonna

Protocol:
  - All commands are binary ECAM packets (header 0x0D, CRC-CCITT seed 0x1D0F)
  - Packets are Base64-encoded with a 4-byte big-endian Unix timestamp appended
  - Written to the `data_request` Ayla property via the cloud API
  - Machine state is read from the `d302_monitor` property

Start:
    docker compose up
    # or: python api.py

Docs:
    http://localhost:8000/docs   (Swagger UI)
    http://localhost:8000/redoc  (ReDoc)
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from binascii import crc_hqx
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

AYLA_USER_BASE  = "https://user-field-eu.aylanetworks.com"
AYLA_ADS_BASE   = "https://ads-eu.aylanetworks.com"
GIGYA_URL       = "https://accounts.eu1.gigya.com/accounts.login"
GIGYA_API_KEY   = "3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2"
AYLA_APP_ID     = "DLonghiCoffeeIdKit-sQ-id"
AYLA_APP_SECRET = "DLonghiCoffeeIdKit-HT6b0VNd4y6CSha9ivM5k8navLw"
CREDS_FILE      = Path(os.environ.get("CREDS_FILE", "/data/credentials.json"))
PROP_MONITOR    = "d302_monitor"
PROP_CMD        = "data_request"

_client: "AylaClient | None" = None


# ---------------------------------------------------------------------------
# ECAM binary protocol
# Source: github.com/Arbuzov/home_assistant_delonghi_primadonna (verified ✓)
# CRC: crc_hqx(all_bytes_except_last_2, seed=0x1D0F) → big-endian last 2 bytes
# ---------------------------------------------------------------------------

def _ecam_finalize(pkt: list[int]) -> bytes:
    """Write CRC-CCITT into the last 2 placeholder bytes of a packet."""
    raw = bytearray(pkt)
    crc = crc_hqx(bytes(raw[:-2]), 0x1D0F)
    raw[-2] = (crc >> 8) & 0xFF
    raw[-1] = crc & 0xFF
    return bytes(raw)


def _ecam_wrap(raw: bytes) -> str:
    """Append 4-byte big-endian Unix timestamp and Base64-encode (matches app Y1())."""
    return base64.b64encode(raw + int(time.time()).to_bytes(4, "big")).decode()


# Packet templates: last 2 bytes are CRC placeholders (0x00 0x00), filled at runtime.
_BREW_PACKETS: dict[str, list[int]] = {
    "espresso":    [0x0d, 0x11, 0x83, 0xf0, 0x01, 0x01, 0x01, 0x00, 0x28, 0x02, 0x03, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00],
    "regular":     [0x0d, 0x0f, 0x83, 0xf0, 0x02, 0x01, 0x01, 0x00, 0x67, 0x02, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00],
    "long":        [0x0d, 0x0f, 0x83, 0xf0, 0x03, 0x01, 0x01, 0x00, 0xa0, 0x02, 0x03, 0x00, 0x00, 0x06, 0x00, 0x00],
    "2x_espresso": [0x0d, 0x0f, 0x83, 0xf0, 0x04, 0x01, 0x01, 0x00, 0x28, 0x02, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00],
    "doppio":      [0x0d, 0x0d, 0x83, 0xf0, 0x05, 0x01, 0x01, 0x00, 0x78, 0x00, 0x00, 0x06, 0x00, 0x00],
    "americano":   [0x0d, 0x12, 0x83, 0xf0, 0x06, 0x01, 0x01, 0x00, 0x28, 0x02, 0x03, 0x0f, 0x00, 0x6e, 0x00, 0x00, 0x06, 0x00, 0x00],
    "hot_water":   [0x0d, 0x0d, 0x83, 0xf0, 0x10, 0x01, 0x0f, 0x00, 0xfa, 0x1c, 0x01, 0x06, 0x00, 0x00],
    "steam":       [0x0d, 0x0d, 0x83, 0xf0, 0x11, 0x01, 0x09, 0x03, 0x84, 0x1c, 0x01, 0x06, 0x00, 0x00],
}

_STOP_PACKETS: dict[str, list[int]] = {
    "espresso":    [0x0d, 0x08, 0x83, 0xf0, 0x01, 0x02, 0x06, 0x00, 0x00],
    "regular":     [0x0d, 0x08, 0x83, 0xf0, 0x02, 0x02, 0x06, 0x00, 0x00],
    "long":        [0x0d, 0x08, 0x83, 0xf0, 0x03, 0x02, 0x06, 0x00, 0x00],
    "2x_espresso": [0x0d, 0x08, 0x83, 0xf0, 0x04, 0x02, 0x06, 0x00, 0x00],
    "doppio":      [0x0d, 0x08, 0x83, 0xf0, 0x05, 0x02, 0x06, 0x00, 0x00],
    "americano":   [0x0d, 0x08, 0x83, 0xf0, 0x06, 0x02, 0x06, 0x00, 0x00],
    "hot_water":   [0x0d, 0x08, 0x83, 0xf0, 0x10, 0x02, 0x06, 0x00, 0x00],
    "steam":       [0x0d, 0x08, 0x83, 0xf0, 0x11, 0x02, 0x06, 0x00, 0x00],
}

_POWER_ON_PACKET  = [0x0d, 0x07, 0x84, 0x0f, 0x02, 0x01, 0x00, 0x00]
_POWER_OFF_PACKET = [0x0d, 0x07, 0x84, 0x0f, 0x01, 0x01, 0x00, 0x00]
_STATUS_PACKET    = [0x0d, 0x05, 0x75, 0x0f, 0x00, 0x00, 0x00]

AVAILABLE_BEVERAGES = list(_BREW_PACKETS.keys())


def build_brew_value(recipe: str) -> str | None:
    """Return Base64-encoded ECAM brew command for a beverage, or None if unknown."""
    pkt = _BREW_PACKETS.get(recipe)
    return _ecam_wrap(_ecam_finalize(list(pkt))) if pkt else None


def build_stop_value(recipe: str) -> str | None:
    pkt = _STOP_PACKETS.get(recipe)
    return _ecam_wrap(_ecam_finalize(list(pkt))) if pkt else None


def build_power_on_value() -> str:
    return _ecam_wrap(_ecam_finalize(list(_POWER_ON_PACKET)))


def build_power_off_value() -> str:
    return _ecam_wrap(_ecam_finalize(list(_POWER_OFF_PACKET)))


def build_status_value() -> str:
    return _ecam_wrap(_ecam_finalize(list(_STATUS_PACKET)))


# ---------------------------------------------------------------------------
# Monitor data decoding (d302_monitor response)
# ---------------------------------------------------------------------------

_STATE_MAP: dict[int, str] = {
    0x00: "off",
    0x01: "standby",
    0x02: "heating",
    0x03: "ready",
    0x04: "dispensing",
    0x05: "ready",
    0x06: "cleaning",
    0x07: "ready",
    0x08: "alarm",
}

_ALARM_MAP: dict[int, str] = {
    0:  "empty_water_tank",
    1:  "coffee_waste_full",
    2:  "descale_alarm",
    3:  "replace_water_filter",
    4:  "coffee_ground_too_fine",
    5:  "coffee_beans_empty",
    6:  "machine_to_service",
    7:  "heater_probe_failure",
    8:  "too_much_coffee",
    9:  "infuser_motor_not_working",
    10: "steamer_probe_failure",
    11: "empty_drip_tray",
    12: "hydraulic_circuit_problem",
}


def decode_monitor(b64: str, updated_at: str | None = None) -> dict[str, Any]:
    """Decode the d302_monitor Base64 blob into human-readable state."""
    raw = base64.b64decode(b64)

    state_byte = raw[9]  & 0xFF if len(raw) > 9  else -1
    sub_state  = raw[10] & 0xFF if len(raw) > 10 else -1
    nozzle     = raw[4]  & 0xFF if len(raw) > 4  else -1

    alarm_word = 0
    if len(raw) >= 14:
        alarm_word = raw[7] | (raw[8] << 8) | (raw[12] << 16) | (raw[13] << 24)
    alarms = [_ALARM_MAP.get(i, f"alarm_{i}") for i in range(32) if (alarm_word >> i) & 1]

    switches = (raw[5] | (raw[6] << 8)) if len(raw) > 6 else 0

    stale, stale_seconds = False, 0
    if updated_at:
        try:
            dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            stale_seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
            stale = stale_seconds > 300
        except Exception:
            pass

    return {
        "state":         _STATE_MAP.get(state_byte, f"unknown(0x{state_byte:02x})"),
        "state_code":    state_byte,
        "sub_state":     sub_state,
        "is_ready":      state_byte in (0x03, 0x05, 0x07),
        "is_on":         bool(switches & 0x01),
        "nozzle":        nozzle,
        "alarms":        alarms,
        "data_updated_at": updated_at,
        "stale":         stale,
        "stale_seconds": stale_seconds,
        "raw_hex":       raw.hex(),
    }


# ---------------------------------------------------------------------------
# Ayla cloud client
# ---------------------------------------------------------------------------

class AylaClient:
    """Ayla Networks cloud API client with automatic token refresh."""

    def __init__(self, refresh_token: str, dsn: str) -> None:
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        self.dsn = dsn
        self.refresh_token = refresh_token
        self.access_token: str | None = None
        self._expires_at: float = 0
        self._lock = threading.Lock()

    def _ensure_token(self) -> None:
        if self.access_token and time.time() < self._expires_at:
            return
        with self._lock:
            if self.access_token and time.time() < self._expires_at:
                return
            self._do_refresh()

    def _do_refresh(self) -> None:
        resp = requests.post(
            f"{AYLA_USER_BASE}/users/refresh_token.json",
            json={"user": {"refresh_token": self.refresh_token}},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if resp.ok:
            data = resp.json()
        else:
            print(f"[auth] Refresh token rejected ({resp.status_code}), falling back to Gigya login...")
            email    = os.environ.get("DELONGHI_EMAIL", "")
            password = os.environ.get("DELONGHI_PASSWORD", "")
            if not email or not password:
                raise RuntimeError(
                    f"Refresh token expired and no DELONGHI_EMAIL/DELONGHI_PASSWORD set. "
                    f"Add them to your .env file."
                )
            data = _gigya_exchange(_gigya_login(email, password))
            print("[auth] Gigya login successful.")
        self.access_token   = data["access_token"]
        self.refresh_token  = data["refresh_token"]
        self._expires_at    = time.time() + data.get("expires_in", 86000) - 300
        self._session.headers["Authorization"] = f"auth_token {self.access_token}"
        self._persist_tokens()
        print(f"[auth] Token refreshed, expires in {data.get('expires_in', '?')}s")

    def _persist_tokens(self) -> None:
        try:
            creds = json.loads(CREDS_FILE.read_text()) if CREDS_FILE.exists() else {}
            creds.setdefault("ayla_api", {})
            creds["ayla_api"]["access_token"]  = self.access_token
            creds["ayla_api"]["refresh_token"] = self.refresh_token
            CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
            CREDS_FILE.write_text(json.dumps(creds, indent=2))
        except Exception as exc:
            print(f"[auth] Could not persist tokens: {exc}")

    def _get(self, path: str, timeout: int = 15) -> Any:
        self._ensure_token()
        resp = self._session.get(f"{AYLA_ADS_BASE}{path}", timeout=timeout)
        _raise(resp)
        return resp.json()

    def devices(self) -> list[dict[str, Any]]:
        return [d["device"] for d in self._get("/apiv1/devices.json")]

    def properties(self, names: list[str] | None = None) -> list[dict[str, Any]]:
        url = f"/apiv1/dsns/{self.dsn}/properties.json"
        if names:
            url += "?names=" + ",".join(names)
        return [p["property"] for p in self._get(url)]

    def get_property(self, name: str) -> dict[str, Any]:
        return self._get(f"/apiv1/dsns/{self.dsn}/properties/{name}.json").get("property", {})

    def send_command(self, value: str) -> dict[str, Any]:
        """Write an ECAM packet (Base64+timestamp) to data_request."""
        self._ensure_token()
        resp = self._session.post(
            f"{AYLA_ADS_BASE}/apiv1/dsns/{self.dsn}/properties/{PROP_CMD}/datapoints.json",
            json={"datapoint": {"value": value}},
            timeout=15,
        )
        _raise(resp)
        return resp.json()

    def set_property(self, name: str, value: Any) -> dict[str, Any]:
        self._ensure_token()
        resp = self._session.post(
            f"{AYLA_ADS_BASE}/apiv1/dsns/{self.dsn}/properties/{name}/datapoints.json",
            json={"datapoint": {"value": value}},
            timeout=15,
        )
        _raise(resp)
        return resp.json()


def _raise(resp: requests.Response) -> None:
    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=resp.text[:300])


def _gigya_login(email: str, password: str) -> str:
    resp = requests.post(
        GIGYA_URL,
        data={"apiKey": GIGYA_API_KEY, "loginID": email, "password": password,
              "include": "id_token", "targetEnv": "mobile"},
        timeout=15,
    )
    data = resp.json()
    if data.get("errorCode", 0) != 0:
        raise RuntimeError(f"Gigya login failed: {data.get('errorMessage', data)}")
    return data["id_token"]


def _gigya_exchange(id_token: str) -> dict[str, str]:
    resp = requests.post(
        f"{AYLA_USER_BASE}/api/v1/token_sign_in",
        data={"app_id": AYLA_APP_ID, "app_secret": AYLA_APP_SECRET, "token": id_token},
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(f"Ayla token exchange failed: {resp.status_code} {resp.text[:200]}")
    return resp.json()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    global _client
    refresh = os.environ.get("REFRESH_TOKEN", "")
    dsn     = os.environ.get("DSN", "")

    if CREDS_FILE.exists():
        try:
            creds    = json.loads(CREDS_FILE.read_text())
            file_rt  = creds.get("ayla_api", {}).get("refresh_token", "")
            file_dsn = creds.get("device", {}).get("dsn", "")
            if file_rt:
                refresh = file_rt
            if file_dsn:
                dsn = dsn or file_dsn
        except Exception as exc:
            print(f"[startup] Warning: could not read credentials file: {exc}")

    if not refresh:
        email    = os.environ.get("DELONGHI_EMAIL", "")
        password = os.environ.get("DELONGHI_PASSWORD", "")
        if email and password:
            print("[startup] No refresh token — logging in via Gigya...")
            refresh = _gigya_exchange(_gigya_login(email, password))["refresh_token"]
        else:
            raise RuntimeError("No REFRESH_TOKEN and no DELONGHI_EMAIL/DELONGHI_PASSWORD found")

    if not dsn:
        raise RuntimeError("No DSN env var and no credentials.json found")

    _client = AylaClient(refresh_token=refresh, dsn=dsn)
    _client._do_refresh()
    print(f"[startup] Machine DSN : {dsn}")
    print(f"[startup] API ready  → http://0.0.0.0:{os.environ.get('PORT', 8000)}/docs")
    yield


app = FastAPI(
    title="DeLonghi Coffee API",
    version="3.0.0",
    description=(
        "Control your DeLonghi coffee machine via REST.\n\n"
        "Uses the verified ECAM binary protocol (CRC-CCITT/crc_hqx seed 0x1D0F) "
        "sent over the Ayla Networks cloud API via the `data_request` property.\n\n"
        "**Supported beverages:** " + ", ".join(AVAILABLE_BEVERAGES)
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _c() -> AylaClient:
    if not _client:
        raise HTTPException(503, "API not initialized")
    return _client


class BrewRequest(BaseModel):
    recipe: str = Field(
        description=f"Beverage name. Available: {', '.join(AVAILABLE_BEVERAGES)}",
        examples=["regular"],
    )


class PropertyWriteRequest(BaseModel):
    value: Any = Field(description="Raw property value to write")


# ── Machine Status ───────────────────────────────────────────────────────────

@app.get("/status", tags=["Machine"], summary="Machine state")
def get_status() -> JSONResponse:
    """
    Decoded machine state from `d302_monitor`.

    Returns `state`, `is_ready`, `is_on`, `alarms`, `raw_hex`.
    `stale=true` means data is >5 min old (machine stops pushing when app disconnects).
    """
    prop  = _c().get_property(PROP_MONITOR)
    value = prop.get("value")
    if not value:
        raise HTTPException(404, "Monitor property not found")
    return JSONResponse(decode_monitor(value, prop.get("data_updated_at")))


@app.get("/devices", tags=["Machine"], summary="List devices")
def list_devices() -> JSONResponse:
    """All machines registered on this Ayla account."""
    return JSONResponse(_c().devices())


@app.get("/stats", tags=["Machine"], summary="Machine statistics")
def get_stats() -> JSONResponse:
    """Beverage counters, grind count, descale water."""
    stat_prefixes = ("d70", "d55", "d27", "d51", "d82")
    return JSONResponse({
        p["name"]: p.get("value")
        for p in _c().properties()
        if any(p.get("name", "").startswith(px) for px in stat_prefixes)
        and p.get("value") is not None
    })


# ── Brew ─────────────────────────────────────────────────────────────────────

@app.get("/beverages", tags=["Brew"], summary="Available beverages")
def list_beverages() -> JSONResponse:
    """List all supported beverage names."""
    return JSONResponse({"beverages": AVAILABLE_BEVERAGES})


@app.post("/brew", tags=["Brew"], summary="Brew a beverage")
def brew(body: BrewRequest) -> JSONResponse:
    """
    Trigger a brew using the ECAM binary protocol.

    Builds the verified binary packet for the requested beverage,
    appends the current Unix timestamp, Base64-encodes it, and writes
    it to the `data_request` Ayla property. The machine starts immediately.
    """
    key   = body.recipe.lower().replace("-", "_").replace(" ", "_")
    value = build_brew_value(key)
    if value is None:
        raise HTTPException(400, f"Unknown beverage '{body.recipe}'. Use GET /beverages.")
    result = _c().send_command(value)
    return JSONResponse({
        "beverage":   key,
        "status":     "sent",
        "updated_at": result.get("datapoint", {}).get("updated_at"),
    })


@app.post("/stop", tags=["Brew"], summary="Stop current brew")
def stop(body: BrewRequest) -> JSONResponse:
    """Stop an in-progress brew. Pass the same beverage name that was started."""
    key   = body.recipe.lower().replace("-", "_").replace(" ", "_")
    value = build_stop_value(key)
    if value is None:
        raise HTTPException(400, f"Unknown beverage '{body.recipe}'.")
    _c().send_command(value)
    return JSONResponse({"beverage": key, "status": "stop_sent"})


# ── Power ─────────────────────────────────────────────────────────────────────

@app.post("/power/on", tags=["Power"], summary="Power on")
def power_on() -> JSONResponse:
    """Wake machine from standby using the ECAM power-on packet."""
    _c().send_command(build_power_on_value())
    return JSONResponse({"power": "on"})


@app.post("/power/off", tags=["Power"], summary="Power off / standby")
def power_off() -> JSONResponse:
    """Put machine into standby using the ECAM power-off packet."""
    _c().send_command(build_power_off_value())
    return JSONResponse({"power": "off"})


# ── Raw Properties ────────────────────────────────────────────────────────────

@app.get("/properties", tags=["Properties"], summary="All properties")
def list_properties() -> JSONResponse:
    """Dump all raw Ayla device properties."""
    return JSONResponse(_c().properties())


@app.get("/properties/{name}", tags=["Properties"], summary="Get property")
def get_property(name: str) -> JSONResponse:
    """Read a single property by name."""
    return JSONResponse(_c().get_property(name))


@app.post("/properties/{name}", tags=["Properties"], summary="Set property")
def set_property(name: str, body: PropertyWriteRequest) -> JSONResponse:
    """Write a raw property value directly (advanced use)."""
    return JSONResponse(_c().set_property(name, body.value))


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/auth/token", tags=["Auth"], summary="Token info")
def auth_info() -> JSONResponse:
    """Current token status (for debugging)."""
    c = _c()
    return JSONResponse({
        "access_token":      c.access_token[:8] + "..." if c.access_token else None,
        "dsn":               c.dsn,
        "token_valid":       time.time() < c._expires_at,
        "expires_in_seconds": max(0, int(c._expires_at - time.time())),
    })


@app.post("/auth/refresh", tags=["Auth"], summary="Force token refresh")
def auth_refresh() -> JSONResponse:
    """Force an immediate token refresh."""
    _c()._do_refresh()
    return JSONResponse({"status": "refreshed"})


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"], summary="Health check")
def health() -> JSONResponse:
    """Liveness probe for Docker / orchestrators."""
    return JSONResponse({"status": "ok", "dsn": _client.dsn if _client else None})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)
