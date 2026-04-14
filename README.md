# ☕ DeLonghi Coffee API

> Control your DeLonghi coffee machine locally via a REST API — no app required.

Reverse-engineered from the official **Coffee Link** Android app. Uses the **ECAM binary protocol** over the Ayla Networks cloud to send commands directly to your machine.

Works with any DeLonghi machine supported by the Coffee Link app (Primadonna, Maestosa, Dinamica, etc.)

---

## Features

- **Brew any beverage** — espresso, regular, long, doppio, americano, hot water, steam
- **Power on / off** from standby
- **Stop** a brew mid-way
- **Machine state** — ready, heating, dispensing, alarms
- **Auto token refresh** — logs back in automatically when the session expires
- **Docker ready** — one command to deploy on a Raspberry Pi or any server
- **REST API + Swagger UI** at `/docs`

---

## How it works

The DeLonghi Coffee Link app doesn't talk directly to the machine over LAN — it routes all commands through the **Ayla Networks IoT cloud**. Each command is a binary **ECAM packet** (16 bytes), encoded in Base64 with a Unix timestamp appended, and written to a cloud property called `data_request`. The machine polls this property and executes the command.

This API reconstructs those packets from scratch using the verified binary format extracted from the APK.

```
Your request → ECAM binary packet → CRC-CCITT → Base64 + timestamp
    → Ayla cloud (data_request property)
    → Machine executes
```

> Full write-up: [reverse engineering a coffee machine with apktool, mitmproxy and jadx](#)

---

## Quick start

### 1. Find your DSN

Open the Coffee Link app → Settings → Device info. Your DSN looks like `AC000W031XXXXXX`.

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your DSN and DeLonghi account credentials
```

### 3. Run with Docker

```bash
docker compose up -d
```

API is live at **http://localhost:8000**
Swagger UI at **http://localhost:8000/docs**

### 4. Make a coffee

```bash
curl -X POST http://localhost:8000/brew \
  -H "Content-Type: application/json" \
  -d '{"recipe": "regular"}'
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/status` | Machine state (ready, heating, standby, alarms…) |
| `GET` | `/beverages` | List available beverages |
| `POST` | `/brew` | Brew a beverage `{"recipe": "regular"}` |
| `POST` | `/stop` | Stop current brew `{"recipe": "regular"}` |
| `POST` | `/power/on` | Wake machine from standby |
| `POST` | `/power/off` | Put machine into standby |
| `GET` | `/stats` | Usage counters (total coffees, descale water, etc.) |
| `GET` | `/health` | Liveness probe for Docker |
| `GET` | `/docs` | Swagger UI |

### Available beverages

`espresso` · `regular` · `long` · `2x_espresso` · `doppio` · `americano` · `hot_water` · `steam`

---

## Deploy on Raspberry Pi

```bash
# Copy files to your Pi
rsync -av . pi@192.168.1.x:~/delonghi-coffee-api/

# SSH in and start
ssh pi@192.168.1.x
cd ~/delonghi-coffee-api
docker compose up -d
```

---

## Running without Docker

```bash
pip install -r requirements.txt

# Set env vars
export DSN=AC000W031XXXXXX
export DELONGHI_EMAIL=your@email.com
export DELONGHI_PASSWORD=yourpassword

python api.py
```

---

## CLI (lan_client.py)

For quick testing without the API server:

```bash
# Status
python lan_client.py status

# Brew
python lan_client.py brew regular
python lan_client.py brew espresso

# Power
python lan_client.py power on
python lan_client.py power off

# Stop
python lan_client.py stop regular
```

---

## How the ECAM protocol works

Each command is a raw binary packet:

```
[0x0D][LEN][CMD_HI][CMD_LO][BEVERAGE_ID][OP][...params][CRC_HI][CRC_LO]
```

- Header is always `0x0D`
- CRC is **CRC-CCITT** computed with seed `0x1D0F` over all bytes except the last two
- Before sending, a **4-byte big-endian Unix timestamp** is appended to the packet, then the whole thing is Base64-encoded

This format was reverse-engineered from `coffee-link.apk` using `apktool` + `jadx`, and validated against the [home_assistant_delonghi_primadonna](https://github.com/Arbuzov/home_assistant_delonghi_primadonna) project.

---

## Compatibility

Tested on:
- DeLonghi Dinamica Plus ECAM370

Should work with any machine using the **Coffee Link** app (ECAM series).

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DSN` | ✅ | Device serial number (from the app) |
| `DELONGHI_EMAIL` | ✅ | Your Coffee Link account email |
| `DELONGHI_PASSWORD` | ✅ | Your Coffee Link account password |
| `REFRESH_TOKEN` | Optional | Auto-populated after first login |
| `CREDS_FILE` | Optional | Path to persist tokens (default: `/data/credentials.json`) |
| `PORT` | Optional | API port (default: `8000`) |

---

## Credits

- Protocol research: [home_assistant_delonghi_primadonna](https://github.com/Arbuzov/home_assistant_delonghi_primadonna) by Arbuzov
- Reverse engineering: apktool, jadx, mitmproxy

---

## License

MIT
