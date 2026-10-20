# API Reference

Base URL: `http://<host>:8000`. Request/response bodies are JSON.

**Auth.** Scan/attack endpoints require the operator token when
`API_AUTH_TOKEN` is set: send `X-API-TOKEN: <token>` (or
`Authorization: Bearer <token>`, or `?token=<token>`). When `API_AUTH_TOKEN` is
empty, auth is bypassed (dev lab default). Agent ingest endpoints use the
separate `AGENT_TOKEN` via `X-AGENT-TOKEN` when configured.

Scan/attack endpoints return `202 Accepted` with a `session_id` (and usually a
`thread_id`); results then stream over the WebSocket for that session, and are
also retrievable via the history/results endpoints.

## Scanning

### POST /api/scan/host-discovery/
Body: `{ "subnet": "192.168.56.0/24" }` → `202 {session_id, thread_id, subnet, status}`.

### POST /api/scan/port-scan/
Body: `{ "ip": "192.168.56.20", "ports": [22,80,443], "protocol": "tcp" }`
(`ports` optional, defaults to 1–1024). → `202 {session_id, thread_id, ...}`.
`400` if `ip` missing or outside `SCAN_ALLOWED_SUBNET`. Unreachable targets emit
a low-severity reachability advisory event rather than aborting.

### POST /api/scan/os-fingerprint/
Body: `{ "ip": "192.168.56.20" }` → `202 {session_id, thread_id, ...}`.

## Attack simulation (lab only)

### POST /api/attack/arp-spoof/
Body: `{ "target_ip": "...", "gateway_ip": "..." }`. Both validated against the
allowed subnet and reachability.

### POST /api/attack/syn-flood/
Body: `{ "target_ip": "...", "target_port": 80 }`.

### POST /api/attack/icmp-redirect/
Body: `{ "target_ip": "...", "spoofed_gateway": "...", "attacker_ip": "...", "destination_ip": "..." }`.

### POST /api/attack/stop/
Body: `{ "thread_id": "<uuid>" }` → stops a running scan/attack thread.

### GET /api/threads/
List background threads and status. **GET /api/threads/&lt;thread_id&gt;/** for one.

## Agent ingest (from lab VMs)

### POST /api/alerts/
Agent-reported alert: `{ agent, type, src_ip, dst_ip, severity, message }`.
Persisted once and broadcast. → `201 {status, session_id, alert_id}`.

### POST /api/packets/
Agent-reported packet: `{ summary, flags, ttl, src_ip, dst_ip, protocol, timestamp }`.
Runs the detection engine and feeds the ML engine. Rate-limited per session
(`429` when exceeded).

### POST /api/agents/inventory/  ·  GET /api/agents/inventory/latest/
Inventory snapshot ingest / latest snapshots.

### GET|POST /api/agents/registry/  ·  GET /api/agents/health/
Registered agents and health (online/offline) state.

## SOC data

### GET /api/alerts/history/&lt;session_id&gt;/?limit=300
### GET /api/packets/history/&lt;session_id&gt;/?limit=500
History for UI refreshes (`session_id` = `live` for the SOC-wide stream).

### GET /api/results/&lt;session_id&gt;/
Hosts, ports and results for a session.

### GET /api/report/&lt;session_id&gt;/pdf/
PDF session report (ReportLab).

### GET /api/hosts/&lt;ip&gt;/risk-score/
Host risk score + breakdown (risky ports, vulns, failed logins).

### GET /api/mitre-mapping/
The MITRE ATT&CK mapping table used to enrich alerts.

### GET /api/mitigations/?limit=100&status=would_block&src_ip=&alert_type=&hours=24
IPS actions. Response: `{ count, enforce, items: [{id, alert_type, src_ip,
dst_ip, severity, action, mode, status, reason, mitre_*, created_at}] }`.

### GET /api/audit-logs/?limit=100&offset=0&action=&status=&hours=24
Audit trail (`scan_started`, `scan_completed`, `fingerprint_run`,
`attack_initiated`, `alert_generated`, `mitigation_recorded`).

## WebSocket

`ws://<host>:8000/ws/scan/<session_id>/[?token=<operator-token>]`

Use `session_id = live` for the SOC-wide stream, `inventory` for inventory.
On connect the server sends `{event_type: "connection_established"}`; if
`API_AUTH_TOKEN` is set and the `?token=` is wrong, the socket closes with code
`4401`. Server pings every ~20s; the client pings every ~25s. Send
`{"type":"ping"}` to get `{"event_type":"pong"}`.

Every frame is a JSON object with an `event_type`:

| event_type | payload (key fields) |
|------------|----------------------|
| `connection_established` | `session_id`, `message` |
| `packet` | `summary`, `flags`, `ttl`, `src_ip`, `dst_ip`, `protocol`, `timestamp` |
| `event` | lifecycle/activity: `type`, `src_ip`, `dst_ip`, `severity`, `message`, `timestamp` |
| `alert` | real detection: `type`, `src_ip`, `dst_ip`, `severity`, `message`, `timestamp`, `mitre_*` |
| `ml_alert` | `type` (`ml_<label>`), `label`, `confidence`, `model_version`, `priority`, `top_features`, `src_ip`, `severity`, `message` |
| `mitigation` | `type`, `src_ip`, `dst_ip`, `severity`, `action`, `mode`, `status`, `reason`, `mitre_*`, `created_at` |
| `host_found` | `ip`, `mac`, ... |
| `port_result` | `ip`, `port`, `status`, `service`, `banner`, `reason`, `method`, `rtt_ms` |
| `os_result` | `ip`, OS guess fields |
| `status` | `session_id`, `status` (running/complete/stopped/failed), `message` |
| `inventory` | inventory update fields (on the `inventory` stream) |
| `ping` / `pong` | heartbeat |

Clients should ignore unknown `event_type`s for forward compatibility.
