# ☕ DeLonghi Coffee API

> Control your DeLonghi coffee machine locally via a REST API — no app required.

Reverse-engineered from the official **Coffee Link** Android app. Uses the **ECAM binary protocol** over the Ayla Networks cloud to send commands directly to your machine. Full technical write-up in [`docs/writeup.md`](docs/writeup.md).

Works with any DeLonghi machine supported by the Coffee Link app (Primadonna, Maestosa, Dinamica, Eletta, etc.)

---

## Features

- **Brew any beverage** — espresso, regular, long, doppio, americano, hot water, steam
- **Power on / off** from standby
- **Stop** a brew mid-way
- **Machine state** — ready, heating, dispensing, alarms
- **Auto token refresh** — re-authenticates via Gigya automatically when the 24h session expires
- **Docker ready** — one command to deploy on a Raspberry Pi or any Linux box
- **Swagger UI** at `/docs`

---

## Repository Structure

```
delonghi-coffee-api/
├── api.py              # FastAPI server — the main deployable
├── lan_client.py       # CLI tool for quick testing
├── Dockerfile
├── compose.yaml
├── requirements.txt
├── .env.example        # Copy to .env and fill in your credentials
├── data/               # Token persistence (git-ignored)
└── docs/
    ├── writeup.md      # Full reverse engineering write-up
    ├── protocol.md     # ECAM binary protocol reference
    └── skills.md       # AI agent quick reference (endpoint list)
```

---

## How It Works

The DeLonghi Coffee Link app does not talk directly to the machine — it routes all commands through the **Ayla Networks IoT cloud**. Each command is a binary **ECAM packet**, appended with a Unix timestamp, Base64-encoded, and written to a cloud property called `data_request`. The machine polls this property and executes the command.

This API reconstructs those packets from scratch using the binary format reverse-engineered from the APK.

```
Your request
  → ECAM binary packet (16 bytes)
  → CRC-CCITT checksum (seed 0x1D0F)
  → append Unix timestamp (4 bytes big-endian)
  → Base64 encode
  → POST to Ayla cloud (data_request property)
  → Machine executes
```

**Full write-up:** [`docs/writeup.md`](docs/writeup.md)
**Protocol reference:** [`docs/protocol.md`](docs/protocol.md)

---

## Quick Start

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

API is live at **http://localhost:8000** · Swagger UI at **http://localhost:8000/docs**

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
| `GET` | `/properties` | All raw Ayla device properties |
| `GET` | `/health` | Liveness probe for Docker |
| `GET` | `/docs` | Swagger UI |

### Available Beverages

`espresso` · `regular` · `long` · `2x_espresso` · `doppio` · `americano` · `hot_water` · `steam`

---

## Deploy on Raspberry Pi

```bash
# Copy files to your Pi
rsync -av --exclude '.git' . tkmremi@192.168.1.x:~/delonghi-coffee-api/

# SSH in and start
ssh tkmremi@192.168.1.x
cd ~/delonghi-coffee-api
cp .env.example .env   # fill in your credentials
docker compose up -d
```

---

## Run Without Docker

```bash
pip install -r requirements.txt

export DSN=AC000W031XXXXXX
export DELONGHI_EMAIL=your@email.com
export DELONGHI_PASSWORD=yourpassword

python api.py
```

---

## CLI (Quick Testing)

```bash
python lan_client.py status
python lan_client.py brew regular
python lan_client.py brew espresso
python lan_client.py stop regular
python lan_client.py power on
python lan_client.py power off
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DSN` | ✅ | Device serial number (from the app) |
| `DELONGHI_EMAIL` | ✅ | Your Coffee Link account email |
| `DELONGHI_PASSWORD` | ✅ | Your Coffee Link account password |
| `REFRESH_TOKEN` | Optional | Auto-populated after first login |
| `CREDS_FILE` | Optional | Token persistence path (default: `/data/credentials.json`) |
| `PORT` | Optional | API port (default: `8000`) |

---

## Compatibility

Tested on DeLonghi Dinamica Plus ECAM370. Should work with any machine in the ECAM series supported by the Coffee Link app.

---

## Security Notes

The ECAM protocol has no payload encryption. The only replay protection is the Unix timestamp — the machine rejects packets older than a few seconds. Authentication is handled entirely by the Ayla cloud layer. Anyone with a valid `access_token` and the right DSN can control the machine.

---

## Credits

Reverse engineering tools: `apktool`, `jadx`, `mitmproxy`

---

## License

MIT
