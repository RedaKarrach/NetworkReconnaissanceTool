# Agents

Two standalone Python scripts — no Docker needed, run directly on the VMs.

| File | VM | Role |
|------|----|------|
| `victim_agent.py` | Windows 10 VM (192.168.56.20) | Sniffs traffic, detects attacks, POSTs alerts to dashboard |
| `attacker.py`     | Kali Linux VM (192.168.56.10) | Launches SYN flood / ARP spoof / ICMP redirect |

## Quick install

```bash
# Both VMs
pip install scapy requests

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

See the main README.md for the full setup guide.
