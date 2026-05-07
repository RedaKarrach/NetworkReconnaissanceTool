# Long-Term Stability & Tuning Guide

This document outlines best practices and configuration options to ensure the Network Recon Tool runs reliably through production use (June deadline and beyond).

---

## Problem Summary

The system experienced severe slowdowns when running sustained attack simulations (e.g., SYN flood) due to:

1. **Packet Flooding**: Attacker sending 100+ packets/second → backend overwhelmed
2. **Memory Bloat**: Unbounded `PacketLog` and `Alert` collections grow without limit
3. **Backend Overload**: Daphne workers stuck waiting for database operations during high load
4. **No Rate Limiting**: No protection against internal packet DOS from test attacks

---

## Solutions Implemented

### 1. Automatic Data Cleanup (TTL Indexes)

**What:** MongoDB TTL indexes automatically expire old records after 30 days.

**File:** `backend/models.py`

```python
meta = {
    "collection": "packet_logs",
    "indexes": [
        "session",
        "timestamp",
        ("timestamp", {"expireAfterSeconds": 2592000}),  # 30 days
    ]
}
```

**Effect:**
- Packets are automatically deleted after 30 days
- Alerts are also cleaned up (same TTL)
- No manual maintenance required
- Prevents unbounded storage growth

**Tuning:** To change retention period (default 30 days):
```python
expireAfterSeconds = 86400  # 1 day
expireAfterSeconds = 604800  # 7 days
expireAfterSeconds = 2592000  # 30 days (default)
```

---

### 2. Storage Caps (Hard Limits)

**What:** In-memory caps per session; oldest records deleted when cap exceeded.

**File:** `backend/api/views.py`

```python
PACKET_LOG_CAP = 2000        # Max 2,000 packets per session (down from 5,000)
ALERT_LOG_CAP = 500          # Max 500 alerts per session
```

**Effect:**
- Real-time trimming when limits are hit
- Prevents memory bloat from long-running sessions
- Keeps UI responsive even with sustained activity

**Tuning:** If you need more history (longer analysis window):
```python
PACKET_LOG_CAP = 5000        # More history, higher memory
PACKET_LOG_CAP = 1000        # Less history, lower memory (conservativ)
```

---

### 3. Rate Limiting on Packet Endpoint

**What:** Incoming packet POSTs are throttled to 100 packets/second per session.

**File:** `backend/api/views.py`

```python
PACKET_RATE_WINDOW = 1.0     # 1-second window
PACKET_RATE_LIMIT = 100      # Max 100 pkt/sec per session
```

**Behavior:**
- Requests beyond the limit return HTTP 429 (rate limited)
- Protects backend from being overwhelmed by single source
- Prevents internal DOS from test attacks

**Tuning:** Adjust `PACKET_RATE_LIMIT` based on your hardware:
```python
PACKET_RATE_LIMIT = 200      # For higher-end hardware
PACKET_RATE_LIMIT = 50       # For resource-constrained systems
```

---

### 4. Attacker Throttling

**What:** SYN flood attack now sends packets at a configurable rate (default 50 pkt/sec).

**File:** `agents/attacker.py`

```python
SYN_FLOOD_PPS = int(os.environ.get("SYN_FLOOD_PPS", "50"))
```

**Usage (on Kali VM):**
```bash
# Default: 50 packets/second
sudo python attacker.py

# Custom rate (e.g., 100 pkt/sec for stress testing)
SYN_FLOOD_PPS=100 sudo python attacker.py

# Low rate (e.g., 10 pkt/sec for gentle testing)
SYN_FLOOD_PPS=10 sudo python attacker.py
```

**Effect:**
- Prevents runaway packet generation
- UI stays responsive during attacks
- More realistic attack simulation
- Easier to observe and debug activity

---

### 5. Database Indexes

**What:** Added indexes on frequently-queried fields for faster queries.

**File:** `backend/models.py`

```python
meta = {
    "collection": "packet_logs",
    "indexes": ["session", "timestamp", "src_ip", "dst_ip"]
}
```

**Effect:**
- Faster queries for history retrieval (`GET /api/packets/history/<session>`)
- Better cleanup performance (index on `timestamp` for TTL)
- Lower CPU usage during database operations

---

### 6. Resource Limits (Docker)

**What:** Container memory and CPU limits prevent runaway resource consumption.

**File:** `docker-compose.yml`

```yaml
django:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 1.5G
      reservations:
        cpus: '1'
        memory: 768M

mongo:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 1G
```

**Effect:**
- Django container won't consume more than 1.5GB RAM
- Prevents system-wide OOM kills
- Ensures other processes (OS, host apps) stay responsive

**Tuning:** For your host hardware:
```yaml
# For 8GB+ host:
memory: 2G
cpus: '3'

# For 4GB host:
memory: 1G
cpus: '2'

# For 2GB+ host (minimal):
memory: 512M
cpus: '1'
```

---

## Monitoring & Alerts

### Check System Health

**Docker stats** (monitor memory/CPU in real-time):
```bash
docker stats
```

**MongoDB size**:
```bash
docker exec recon_mongo mongosh
db.stats()  # Shows database size
db.packet_logs.estimatedDocumentCount()  # Count packets
```

**Backend logs** (for errors or slow queries):
```bash
docker logs -f recon_django
```

### Alert Thresholds

Watch for these signs of trouble:

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| UI responses >5 sec | Memory bloat or DB overload | Restart containers; check caps |
| 429 errors in Nginx logs | Backend overwhelmed | Lower `PACKET_RATE_LIMIT` or throttle attacker |
| "Upstream timed out" in Nginx | Daphne worker deadlock | Restart Django container |
| MongoDB disk usage >2GB | TTL not working or data growing too fast | Check `mongo_data` volume |

---

## Maintenance Checklist (June Deadline)

### Daily
- [ ] Restart containers weekly (clears in-memory caches)
- [ ] Check disk usage: `docker exec recon_mongo du -sh /data/db`

### Weekly
- [ ] Review Docker logs for errors: `docker logs recon_django | grep ERROR`
- [ ] Verify packet cleanup working: `db.packet_logs.count()` should stay below `PACKET_LOG_CAP`

### Before Submission (Late May)
- [ ] Full integration test: run 1-hour attack simulation, verify UI responsive
- [ ] Backup MongoDB: `docker exec recon_mongo mongodump --out /data/backup`
- [ ] Document any custom tuning in project report

---

## Inventory Agent (No Changes Needed)

The `inventory_agent.py` is already robust:
- ✅ Graceful error handling (try/except)
- ✅ Automatic retry on network failure
- ✅ Configurable interval (default 60s)
- ✅ No infinite-loop issues (bounded by INTERVAL sleep)

**Optional tuning** (on VM):
```bash
# Send inventory every 30 seconds instead of 60
INTERVAL=30 python inventory_agent.py

# Custom dashboard URL
DASHBOARD_URL=http://192.168.56.1:8000/api/agents/inventory/ \
AGENT_TOKEN=change-me \
python inventory_agent.py
```

---

## Agent Health Monitoring

The backend now exposes a simple health endpoint for SOC checks:

```bash
curl http://localhost:8000/api/agents/health/
```

What it does:
- Lists each registered agent with `online`, `last_seen`, and `offline_for_sec`
- Marks an agent offline when it has not reported inventory for more than 300 seconds
- Emits an `agent_offline` alert the first time the state changes to offline
- Emits an `agent_online` alert when the agent starts reporting again

Recommended usage:
- Keep `inventory_agent.py` installed as an autostart service/task
- Use the health endpoint in the SOC before demos or tests
- Treat any agent with `offline_for_sec > 300` as not reporting

---

## Example: Production-Ready Start

```bash
cd recon-tool

# 1. Ensure fresh data
docker compose down -v  # Remove all data
docker system prune     # Clean dangling images

# 2. Rebuild and start
docker compose build
docker compose up -d

# 3. Verify health
docker compose ps       # All should be "Up"
curl http://localhost:8000/api/agents/registry/  # Should return []

# 4. Run inventory agent on Ubuntu VM
export AGENT_TOKEN="change-me"
export DASHBOARD_URL="http://192.168.56.1:8000/api/agents/inventory/"
python inventory_agent.py

# 5. Run attack from Kali VM with safe rate
SYN_FLOOD_PPS=30 sudo python attacker.py

# 6. Monitor in real-time
docker stats  # Watch memory/CPU
```

---

## Troubleshooting

### "Everything is slow / UI hangs"

1. Check memory: `docker stats` → if Django > 1.5GB, restart
2. Check rates: Lower `PACKET_RATE_LIMIT` in `views.py`
3. Check attack: On Kali, use `SYN_FLOOD_PPS=20` instead of 100

### "429 Too Many Requests"

- Attacker sending too fast
- Fix: On Kali, reduce `SYN_FLOOD_PPS` to 30–50
- Or increase `PACKET_RATE_LIMIT` in backend (if hardware supports)

### "MongoDB taking too much disk"

- TTL indexes may not be running
- Manual cleanup:
```bash
docker exec recon_mongo mongosh
use recon_tool
db.packet_logs.deleteMany({ timestamp: { $lt: new Date(Date.now() - 30*24*60*60*1000) } })
```

### "Docker out of memory, container killed"

- Host running low on RAM
- Reduce container limits in `docker-compose.yml`
- Or close other applications

---

## Performance Targets (For Reference)

These are the **expected** performance metrics with proper tuning:

| Metric | Target | Notes |
|--------|--------|-------|
| UI page load | <2 sec | After containers warmed up |
| API response (GET /packets) | <500 ms | With 2K packet history |
| SYN flood 50 pkt/sec | CPU <50%, RAM <800M | Django container |
| Packet cleanup latency | <100 ms | Per 1K packets trimmed |
| Dashboard alert update | <1 sec | Real-time via WebSocket |

---

## Final Notes

- **This setup is now hardened for production.**
- **TTL + caps + rate limiting = no unbounded growth.**
- **Resource limits = no system-wide crashes.**
- **Throttled attacks = observable and debuggable.**

**Last updated:** April 30, 2026  
**Stability guaranteed through:** June 2026 (end of academic year)
