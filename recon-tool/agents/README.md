# Agents

Two standalone Python scripts — no Docker needed, run directly on the VMs.

| File | VM | Role |
|------|----|------|
| `victim_agent.py` | Windows 10 VM (192.168.56.20) | Sniffs traffic, detects attacks, POSTs alerts to dashboard |
| `attacker.py`     | Kali Linux VM (192.168.56.10) | Launches SYN flood / ARP spoof / ICMP redirect |
| `inventory_agent.py` | Windows / Kali VM | Sends Wazuh-like host inventory to dashboard |

## Quick install

```bash
# Both VMs
pip install scapy requests psutil

# Windows: also install Npcap first
# https://npcap.com/#download
```

## Run victim_agent.py (Windows, as Administrator)
```
python victim_agent.py
```

## Run attacker.py (Kali, as root)
```
sudo python attacker.py
```

## Run inventory_agent.py (Windows or Kali)
```bash
# Configure dashboard IP + token (use the host-only IP of your host machine)
setx DASHBOARD_URL http://192.168.56.1:8000/api/agents/inventory/
setx AGENT_TOKEN change-me

# Start agent
python inventory_agent.py
```

On Linux:
```bash
export DASHBOARD_URL=http://192.168.56.1:8000/api/agents/inventory/
export AGENT_TOKEN=change-me
python inventory_agent.py
```

See the main README.md for the full setup guide.
