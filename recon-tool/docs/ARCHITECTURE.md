# Architecture

## Components

| Layer | Tech | Responsibility |
|-------|------|----------------|
| Frontend | React 18 + Tailwind | SOC dashboard: alerts, events, packets, endpoints, inventory, network map, risk, audit; live over WebSocket |
| API / ASGI | Django 4.2 + DRF + Channels 4 (Daphne) | REST endpoints, WebSocket consumer, orchestration |
| Channel layer | Redis (`channels_redis`) | Delivers broadcasts from worker threads to WebSocket groups |
| Data store | MongoDB (MongoEngine) | Sessions, hosts, ports, alerts, packets, attacks, inventory, risk, audit, mitigations |
| Auth DB | SQLite | Django's built-in auth only |
| Scanners/attacks | Scapy (in-process, threaded) | Discovery, port scan, fingerprint, ARP/SYN/ICMP attacks |
| Detection engine | `scanner/detection.py` | ARP/sweep/flood/ICMP detection, MITRE mapping, host risk |
| IPS | `MitigationAction` + `_apply_mitigation` | Recommended/enforced response per detection |
| ML | `recon-tool/ml/` + `backend/ml_bridge.py` | Flow features, classifier + IsolationForest, triage, live scoring |
| Agents | Scapy scripts on lab VMs | Report packets/alerts/inventory to the backend |

## Request & streaming flow

```
Operator (dashboard / REST)
     │  POST /api/scan/port-scan/           (OperatorTokenPermission)
     ▼
Django APIView ──► start background thread (threads/manager.py)
     │                     │
     │                     ├─ Scapy scan/attack
     │                     ├─ persist to MongoDB (MongoEngine)
     │                     └─ broadcast_* (consumers.py)
     │                             │  async_to_sync(group_send)
     ▼                             ▼
Response 202 (session_id)    Redis channel layer  ── delivers ──►  ScanConsumer
                                                                       │
                                                                 WebSocket frame
                                                                       ▼
                                                              React useWebSocket
```

The critical property: broadcasts originate in **worker threads**, not the ASGI
loop. Redis (not the in-memory layer) is what makes that delivery reliable.

## Detection → IPS → ML path

```
Agent packet ─ POST /api/packets/ ─► InboundPacketView
     │
     ├─ detection.process_packet()  ─► on real detection ─► _emit_alert()
     │                                        │
     │                                        ├─ persist Alert (once + live mirror)
     │                                        ├─ audit_log("alert_generated")
     │                                        ├─ per-signature cooldown (anti-storm)
     │                                        ├─ broadcast_alert (event_type=alert)
     │                                        └─ _apply_mitigation()
     │                                               ├─ MitigationAction (would_block | enforced)
     │                                               ├─ audit_log("mitigation_recorded")
     │                                               └─ broadcast_mitigation (event_type=mitigation)
     │
     └─ ml_bridge.feed_packet() ─► FlowAggregator ─► MLEngine.score
                                         │  (ML_ENABLED + artifacts)
                                         └─ on detection ─► AlertTriage ─► broadcast_ml_alert
```

Lifecycle events (scan/attack start-complete, agent up/down, reachability
advisories) go through `_emit_event()` → `broadcast_event` (`event_type=event`)
and are **not** written to the Alert collection, keeping the alert feed limited
to real detections.

## Detection engine

One engine in `scanner/detection.py`, entered through `process_packet` (the
single dispatch used by `InboundPacketView`). Signatures:

| Signature (`type`) | Trigger |
|--------------------|---------|
| `arp_anomaly` | same IP, changed MAC within a session |
| `port_sweep` | ≥ `IDS_SWEEP_THRESHOLD` distinct ports from a source / window |
| `host_sweep` | one source hits ≥ `IDS_HOST_SWEEP_THRESHOLD` distinct hosts / window |
| `flood_detected` | ≥ `IDS_SYN_THRESHOLD` SYNs to a dst:port / window |
| `stealth_scan` | NULL / FIN / XMAS / SYN-FIN / unusual TCP flag combos |
| `rst_flood` | high rate of RST packets / window |
| `connection_flood` | ≥ `IDS_CONN_RATE_THRESHOLD` packets from one source / window |
| `udp_flood` | ≥ `IDS_UDP_FLOOD_THRESHOLD` datagrams to a dst:port / window |
| `icmp_flood` | ≥ `IDS_ICMP_FLOOD_THRESHOLD` ICMP packets to a host / window |
| `ping_sweep` | ICMP echo to ≥ `IDS_PING_SWEEP_THRESHOLD` hosts / window |
| `icmp_redirect` | ICMP type 5 observed |
| `dns_anomaly` | ≥ `IDS_DNS_THRESHOLD` DNS queries from a source / window |
| `suspicious_port_access` | connection attempt to a sensitive service (Telnet, SMB, RDP, VNC, Redis, Mongo, …) |
| `land_attack` | packet with identical source and destination |

Windowed counters live in `_windows[store][session][key]`; per-signature
de-dupe/cooldown is handled by the emitter. `check_arp`/`check_port_sweep`/
`check_syn_flood` remain callable for the discovery and attack flows. The VM
agents report `dst_port`, `src_port`, `length`, `icmp_type`, and UDP packets so
the engine has the data these signatures need.

The engine only **builds** alert dicts; `api.views._emit_alert` is the single
persistence/broadcast/cooldown point. The operator's own scans do **not**
self-trigger sweep detection — detection runs on observed/agent traffic.

## IPS / response layer

`_apply_mitigation` maps a confirmed detection to an action
(`block_src_ip` / `quarantine_host` / `monitor`), enriched with the MITRE
mapping. With `IPS_ENFORCE=false` (default) the action is recorded as
`would_block` and surfaced to the UI and audit log. With `IPS_ENFORCE=true` it
is marked `enforced`, but **no real packet dropping / host quarantine is
performed** — that is a deliberate, documented lab-only integration point, not
executed by this code.

## Auth

- REST scan/attack endpoints use `OperatorTokenPermission` (header
  `X-API-TOKEN`, `Authorization: Bearer`, or `?token=`).
- The WebSocket checks `?token=` in `connect` and closes with code `4401` on
  mismatch.
- Both bypass when `API_AUTH_TOKEN` is empty (documented dev default).
- Agent ingest endpoints use the separate `AGENT_TOKEN`.

## Data retention

Packet logs are capped per session (`PACKET_LOG_CAP`), alerts per session
(`ALERT_LOG_CAP`), and inventory by age; trimming runs on write.
