# ReconTool — Network Recon & SOC / NIDS Dashboard

A network reconnaissance tool and Security Operations Center (SOC) dashboard
built for an authorized academic lab (Projet de Fin d'Études). It performs host
discovery, port scanning and OS fingerprinting, simulates a small set of attacks
on isolated lab VMs, detects those attacks with an IDS engine, records
recommended IPS responses, and scores live traffic with classic machine
learning — all streamed live to a React dashboard over WebSockets.

> ⚠️ **AUTHORIZED LAB USE ONLY.** The offensive modules (ARP spoof, SYN flood,
> ICMP redirect) and the scanners generate real attack and probe traffic. Run
> them **only** against machines you own, on an isolated host-only network
> (default `192.168.56.0/24`). Using them against systems you do not own is
> illegal. This project is for education and defensive research.

---

## What it does

- **Reconnaissance** — ARP host discovery, TCP SYN / UDP port scanning with
  banner grabbing, and multi-signal OS fingerprinting (TTL, TCP window, Xmas
  probe).
- **Attack simulation (lab only)** — ARP spoofing, SYN flood, ICMP redirect,
  driven from the dashboard, with a subnet + reachability guard on every target.
- **IDS** — one detection engine spots ARP anomalies, port sweeps, SYN floods
  and ICMP redirects on observed/agent traffic, with env-tunable thresholds and
  MITRE ATT&CK mapping.
- **IPS / response** — every confirmed detection produces a recommended
  mitigation (block / quarantine / monitor). Enforcement is off by default
  (records "would block" only); real enforcement is lab-only.
- **Live SOC dashboard** — alerts, activity events, packets, endpoints,
  inventory, a network map, host risk scores and an audit trail, all streamed
  live (no refresh) over WebSockets.
- **Classic ML + triage** — a RandomForest/GradientBoosting classifier and an
  IsolationForest score live flows; an alert-triage layer deduplicates and
  prioritizes so real threats surface above lifecycle noise.

---

## Architecture

```
  Host 192.168.56.1
  ┌─────────────────────────────────────────────────────────┐
  │  docker compose up                                       │
  │                                                         │
  │  React (nginx) :3000 ──REST/WebSocket──► Django/Daphne :8000
  │                                           │   │   │     │
  │                                        Redis Mongo  Scapy│
  │                                     (channels)(data)(raw)│
  └───────────────────────────┬─────────────────────────────┘
                              │  host-only vboxnet0 192.168.56.0/24
                ┌─────────────┴──────────────┐
                │                            │
          Kali VM .10                  Windows / Ubuntu victim .20
          (attacker.py)                (victim_agent.py, inventory_agent.py)
```

- **Backend** — Django 4.2 + Django Channels 4 (Daphne/ASGI). Scan/attack work
  runs in background threads; results persist to MongoDB (MongoEngine) and stream
  to clients through a **Redis** channel layer.
- **Frontend** — React 18 + Tailwind, a calm flat SOC design system.
- **Agents** — Scapy scripts on the lab VMs report packets/alerts/inventory back
  to the backend.
- **ML** — `recon-tool/ml/`, a separate classic-ML package (training + live
  scoring), bridged into the backend.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for components and data flow,
and [docs/API.md](docs/API.md) for every endpoint and the WebSocket protocol.

---

## The real-time pipeline (important)

Scans and attacks run in background threads and broadcast packets/alerts with
`async_to_sync(group_send)`. The original build used Django's
`InMemoryChannelLayer`, whose queues are bound to the Daphne event loop, so a
`group_send` from a worker thread was silently dropped — alerts saved to Mongo
but never streamed live.

The fix is a **Redis channel layer** (`channels_redis`). Redis is an external
broker, so cross-thread/cross-process broadcasts are delivered reliably. A
server + client WebSocket heartbeat keeps idle connections alive. See
[docs/ANALYSIS.md](docs/ANALYSIS.md).

Streams are split by `event_type`:

| event_type | meaning |
|------------|---------|
| `packet` | raw packet summary |
| `event` | lifecycle/activity (scan started/complete, attack launched, agents) |
| `alert` | real security detection |
| `ml_alert` | machine-learning detection (AI badge + confidence/priority) |
| `mitigation` | IPS recommended/enforced response |
| `host_found` / `port_result` / `os_result` / `status` / `inventory` | scan + inventory updates |
| `ping` / `pong` | heartbeat |

---

## Setup

### Option A — Docker (recommended)

```bash
cd recon-tool
cp .env.example .env            # edit secrets for anything beyond local lab
docker compose up --build
```

Services: `mongo`, **`redis`**, `django` (:8000), `react` (:3000). Open
<http://localhost:3000>. Django has `NET_ADMIN`/`NET_RAW` for Scapy.

### Option B — Local dev

Backend:

```bash
cd recon-tool/backend
python -m venv .venv && . .venv/Scripts/activate     # Windows; use bin/activate on *nix
pip install -r requirements.txt
# Need MongoDB and Redis reachable; for local dev point at localhost:
export MONGO_URI=mongodb://127.0.0.1:27017/recon_db
export REDIS_URL=redis://127.0.0.1:6379/0
python manage.py migrate --run-syncdb
daphne -b 0.0.0.0 -p 8000 config.asgi:application
```

Frontend:

```bash
cd recon-tool/frontend
npm install
npm start          # dev server on :3000
# or: npm run build # production bundle
```

> Without Redis, set `CHANNEL_LAYER_BACKEND=memory` to boot — but live streaming
> from worker threads will not work (that is the bug Redis fixes). Use it for
> unit tests only.

### Lab agents

Deploy the Scapy agents to the VMs (`scripts/deploy_agents.ps1` /
`deploy_agents.sh`) and run, e.g. `agents/attacker.py` on Kali and
`agents/victim_agent.py` on the victim. See `agents/README.md`.

---

## Running scans and attacks

From the dashboard (Scan Tools / Attack Console) or via REST
([docs/API.md](docs/API.md)), for example:

```bash
# Port scan a lab host
curl -X POST http://localhost:8000/api/scan/port-scan/ \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.56.20","ports":[22,80,443,445,3389]}'
```

If `API_AUTH_TOKEN` is set, add `-H "X-API-TOKEN: <token>"` (and the WebSocket
uses `?token=<token>`). Left empty, auth is bypassed for the local lab.

---

## Machine learning

`recon-tool/ml/` is a self-contained classic-ML package (no deep learning).

```bash
pip install -r ml/requirements.txt
# Download CIC-IDS2017 into ml/datasets/ (see ml/datasets/README.md), then:
python ml/train.py --data ml/datasets --model rf --out ml/artifacts
# Enable live scoring:
export ML_ENABLED=true
```

With `ML_ENABLED=true` and artifacts present, the backend scores live flows and
streams `ml_alert` events (AI badge, confidence, triage priority). Missing
package/deps/artifacts → ML silently stays off. See
[ml/MODEL_CARD.md](ml/MODEL_CARD.md).

---

## Environment reference

| Variable | Default | Purpose |
|----------|---------|---------|
| `MONGO_URI` | `mongodb://mongo:27017/recon_db` | MongoEngine connection |
| `REDIS_URL` | `redis://redis:6379/0` | Channels layer broker |
| `CHANNEL_LAYER_BACKEND` | `redis` | `memory` forces in-memory (tests only) |
| `DJANGO_SECRET_KEY` | dev value | Django secret |
| `DEBUG` | `True` | Django debug |
| `SCAN_ALLOWED_SUBNET` | `192.168.56.0/24` | scan/attack target allow-list |
| `AGENT_TOKEN` | empty | shared token for agent ingest endpoints |
| `API_AUTH_TOKEN` | empty | operator token for scan/attack + WS (empty = dev bypass) |
| `REACT_APP_API_TOKEN` | empty | token the frontend sends |
| `IDS_SWEEP_THRESHOLD` | `10` | distinct ports for a port-sweep alert |
| `IDS_SWEEP_WINDOW` | `10` | sweep window (s) |
| `IDS_SYN_THRESHOLD` | `200` | SYNs for a flood alert |
| `IDS_SYN_WINDOW` | `10` | SYN window (s) |
| `IDS_GENERIC_WINDOW` | `10` | window (s) for the rate-based detectors below |
| `IDS_HOST_SWEEP_THRESHOLD` | `10` | distinct hosts for a host-sweep alert |
| `IDS_CONN_RATE_THRESHOLD` | `300` | packets/window from one source → connection flood |
| `IDS_UDP_FLOOD_THRESHOLD` | `200` | datagrams/window → UDP flood |
| `IDS_ICMP_FLOOD_THRESHOLD` | `100` | ICMP packets/window → ICMP flood |
| `IDS_PING_SWEEP_THRESHOLD` | `10` | distinct hosts pinged → ping sweep |
| `IDS_DNS_THRESHOLD` | `100` | DNS queries/window → DNS anomaly |
| `ALERT_COOLDOWN_SECONDS` | `10` | per-signature alert cooldown |
| `IPS_ENFORCE` | `false` | `true` marks actions enforced (still lab-only; no real blocking) |
| `ML_ENABLED` | `false` | enable live ML scoring |
| `ML_CONFIDENCE_THRESHOLD` | `0.7` | min classifier confidence to alert |
| `ML_MIN_PACKETS` | `20` | min packets per source before scoring |
| `ML_WINDOW_SECONDS` | `10` | flow aggregation window |
| `ML_SCORE_INTERVAL` | `2` | seconds between scoring passes |

---

## Validation

```bash
cd recon-tool/backend && python manage.py check
docker compose config                          # compose is valid
REDIS_URL=redis://localhost:6379/0 python tests/smoke_ws.py   # live-stream smoke test
cd ../frontend && npm run build                # clean production build
```

---

## Screenshots

_Placeholder — add dashboard, alerts, network map, and ML/triage screenshots._

| | |
|---|---|
| SOC Monitor | _tbd_ |
| Network Map | _tbd_ |
| Attack Console | _tbd_ |
| Alerts + AI triage | _tbd_ |

---

## Ethics & legal

This tool exists for an authorized, isolated academic lab. The offensive
modules, scanners, and IPS layer must never be pointed at networks or hosts you
are not explicitly authorized to test. The authors accept no liability for
misuse. Unauthorized scanning or attacks are illegal in most jurisdictions.
