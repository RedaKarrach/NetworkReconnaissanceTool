# Analysis & Baseline (Phase 0)

Audit of `recon-tool/` confirming the issues targeted by the SOC revamp. Line
references are against the `feat/soc-revamp` branch point (commit `54a83a8`).

## Baseline

- `python manage.py check` → **System check identified no issues (0 silenced).**
  (Scapy prints a Wireshark `manuf` warning and a TripleDES deprecation warning
  on import; neither is an error.)
- Stack: Django 4.2.9, Channels 4.0.0, MongoEngine 0.27.0, Scapy 2.5.0, React 18.
- Environment limits for this audit host: Docker daemon is not running and
  `docker` is not on PATH; Redis is not installed; Scapy raw-socket scans need
  root and a lab network. Live packet/attack validation must run on the lab VMs.

## Confirmed issues

### 1. Real-time alerts don't stream (top priority)

- `backend/config/settings.py:80` sets `CHANNEL_LAYERS` to
  `channels.layers.InMemoryChannelLayer`.
- Alerts/packets are broadcast from background `threading.Thread` workers via
  `async_to_sync(channel_layer.group_send)` in
  `backend/websockets/consumers.py` (`broadcast_packet`/`broadcast_alert`/
  `broadcast_status`/`broadcast_inventory`).
- `InMemoryChannelLayer` queues live on the Daphne event loop. A `group_send`
  issued with `async_to_sync` from a **different** thread targets a loop that
  thread does not own, so the message is dropped. Alerts still persist to Mongo
  and appear via `/api/alerts/history/<session_id>/` on refresh, but never
  stream live. **Confirmed.**

### 2. `OSFingerprintView` NameError

- Historically `OSFingerprintView` used `thread_id_ref["id"]` without defining
  `thread_id_ref`. The pre-revamp commit `f73e033` already added
  `thread_id_ref = {"id": None}` at `backend/api/views.py:766`. **Already fixed
  in the committed WIP**; Phase 2 verifies no remaining undefined use.

### 3. Detection alerts persisted 2–3×

- `scanner/detection.py` `check_arp` / `check_port_sweep` / `check_syn_flood`
  each call `_save_alert(...)` which does `Alert(...).save()`
  (`detection.py:150`).
- They then invoke `on_alert(alert)` which in every view is
  `lambda a: _emit_alert(session, a)`.
- `_emit_alert` (`backend/api/views.py:132`) calls its own nested `_save_alert`
  for the session **and** for the `live` session (`views.py:151` and `:154`).
- Net effect: one detected event is written up to **3×** (detection engine +
  session mirror + live mirror). History shows duplicates. **Confirmed.**

### 4. IDS detects its own scan

- `PortScanView` calls
  `detection.check_port_sweep(session, "scanner", res["port"], ...)` for every
  probed port (`backend/api/views.py:636`).
- `check_port_sweep` threshold is `PORT_SWEEP_THRESHOLD = 3` distinct ports in
  `PORT_SWEEP_WINDOW = 10s` (`detection.py`). The tool's own scan trivially
  exceeds this, so it alerts on itself. **Confirmed.**

### 5. Lifecycle events buried in the alert feed

- Lifecycle/info events (`host_discovery_start`, `*_complete`,
  `host_found`, scan/attack start-stop, agent online/offline, reachability
  warnings) are emitted through `_emit_alert`, so they land in the same alert
  stream as real detections (e.g. `views.py:562`, `:650`, `:722`, `:732`).
  There is no `event_type` separation between "activity" and "alert".
  **Confirmed.**

### 6. Duplicate pages and dead code

- `frontend/src/pages/Login.jsx` **and** `LoginPage.jsx`
  (`App.jsx` imports `LoginPage`).
- `frontend/src/pages/Dashboard.jsx` **and** `SOCDashboard.jsx`.
- `frontend/src/pages/Endpoints.jsx` **and** `Inventory.jsx`.
- The triple `thread_id_ref = {"id": None}` in `PortScanView` has already been
  reduced to one in the committed WIP (`views.py:599`). **Confirmed.**

### 7. No auth on scan/attack endpoints or the WebSocket

- Scan/attack `APIView`s have no `permission_classes`; the WebSocket
  `ScanConsumer` accepts any connection (`consumers.py` `connect`).
- `AGENT_TOKEN` is only checked for agent ingest (`_check_agent_token`).
  **Confirmed.**

## Also observed (addressed opportunistically)

- `InboundAlertView` saves an `Alert` directly (`views.py:1749`) **and** calls
  `_emit_alert` which saves again → duplicate even for agent-reported alerts.
- Inbound packet detection logic is inlined in `InboundPacketView`
  (`views.py:1823-1868`) rather than living in the detection engine.
- `_emit_alert` also re-broadcasts every alert as a synthetic `packet` event
  (`views.py:164-179`), which pollutes the packet inspector.

## Plan of record

Phases 1–7 as specified in the run kit: fix the channel layer first, then the
correctness bugs, then consolidate detection + add an IPS/response layer + auth,
then the UI design system and page consolidation, then the classic-ML + triage
module, then docs, then validation.
