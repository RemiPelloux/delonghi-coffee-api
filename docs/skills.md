# DeLonghi Coffee Machine — API Skills

Base URL: `http://192.168.3.55:8000`

---

## Make a coffee

```
POST /brew
{"recipe": "<beverage>"}
```

Available beverages: `espresso`, `regular`, `long`, `2x_espresso`, `doppio`, `americano`, `hot_water`, `steam`

Examples:
- Make a regular coffee → `POST /brew` `{"recipe": "regular"}`
- Make an espresso → `POST /brew` `{"recipe": "espresso"}`
- Make a long coffee → `POST /brew` `{"recipe": "long"}`

---

## Stop a brew in progress

```
POST /stop
{"recipe": "<same beverage that was started>"}
```

---

## Power

```
POST /power/on    → wake machine from standby
POST /power/off   → put machine into standby
```

---

## Machine state

```
GET /status
```

Returns: `state` (ready / standby / heating / dispensing / alarm), `is_ready` (bool), `is_on` (bool), `alarms` (list).

If `stale: true` → data is old (open the DeLonghi app briefly to refresh).

---

## List beverages

```
GET /beverages
```

---

## Stats (usage counters)

```
GET /stats
```

Returns total espressos made, total coffees, descale water qty, etc.

---

## Health check

```
GET /health   → {"status": "ok"}
```

---

## Swagger UI (full docs)

`http://192.168.3.55:8000/docs`
