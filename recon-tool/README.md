# Network Intrusion Detection System (NIDS)
## Projet de Fin d'Annee 

  LAB UNIQUEMENT — réseau VirtualBox isolé, jamais sur un réseau tiers.

---

## Architecture

```
  Machine Hôte 192.168.56.1
  ┌─────────────────────────────────────────┐
  │  docker-compose up                      │
  │  Django :8000  ──WebSocket──►  React :3000 │
  │  MongoDB                                │
  └──────────────────┬──────────────────────┘
                     │  vboxnet0 192.168.56.0/24
          ┌──────────┴──────────────┐
          │                         │
  Kali VM .10                 Windows VM .20
  attacker.py  ──ATTAQUE──►  victim_agent.py
  (SYN/ARP)                  POST /api/alerts/
```

---

## ÉTAPE 1 — Réseau VirtualBox

```
VirtualBox → Fichier → Outils → Gestionnaire de réseau
→ Réseaux hôte uniquement → Créer
  IPv4 : 192.168.56.1 / 255.255.255.0
  DHCP : Activé (101 → 254)

Chaque VM → Paramètres → Réseau → Adaptateur 1
  Connecté à : Réseau hôte uniquement → vboxnet0
```

IPs fixes :
```bash
# Kali
sudo ip addr add 192.168.56.10/24 dev eth0

# Windows (PowerShell Admin)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.20 -PrefixLength 24
```

---

## ÉTAPE 2 — Dashboard (machine hôte)

```bash
cd recon-tool
docker-compose up --build
```

- Dashboard : http://localhost:3000
- API       : http://localhost:8000/api/

---

## ÉTAPE 3 — Agents VM

### Quick start for autostart + health

1. Install the agent once with `--install-autostart` on each VM.
2. Reboot the VM.
3. Check the agent health on the backend with:

```bash
curl http://localhost:8000/api/agents/health/
```

4. If an agent stops reporting inventory for more than 5 minutes, the backend marks it offline and emits an `agent_offline` alert.
5. If the agent comes back later, the next inventory heartbeat marks it online again and emits an `agent_online` alert.

### Windows 10 VM

```powershell
# 1. Installer Npcap : https://npcap.com
# 2. Installer deps
pip install scapy requests psutil
# 3. One-time autostart install (PowerShell Admin)
python agents/inventory_agent.py --agent-id windows10 --agent-token change-me --dashboard-url http://192.168.56.1:8000/api/agents/inventory/ --install-autostart
python agents/victim_agent.py --agent-name windows10 --dashboard-url http://192.168.56.1:8000/api/alerts/ --packet-url http://192.168.56.1:8000/api/packets/ --install-autostart

# 4. Run now (without reboot)
python agents/inventory_agent.py --agent-id windows10 --agent-token change-me --dashboard-url http://192.168.56.1:8000/api/agents/inventory/
python agents/victim_agent.py --agent-name windows10 --dashboard-url http://192.168.56.1:8000/api/alerts/ --packet-url http://192.168.56.1:8000/api/packets/

# 5. Removal
python agents/inventory_agent.py --uninstall-autostart
python agents/victim_agent.py --uninstall-autostart
```

### Ubuntu VM

```bash
# 1. Installer deps
pip3 install requests psutil scapy

# 2. Copy agent scripts to VM
scp agents/inventory_agent.py ubuntu@192.168.56.x:~/Desktop/
scp agents/victim_agent.py ubuntu@192.168.56.x:~/Desktop/

# 3. One-time autostart install (systemd service, root/sudo)
sudo python3 ~/Desktop/inventory_agent.py --agent-id ubuntu-vm --agent-token change-me --dashboard-url http://192.168.56.1:8000/api/agents/inventory/ --install-autostart
sudo python3 ~/Desktop/victim_agent.py --agent-name ubuntu-vm --dashboard-url http://192.168.56.1:8000/api/alerts/ --packet-url http://192.168.56.1:8000/api/packets/ --install-autostart

# 4. Run now (without reboot)
sudo python3 ~/Desktop/inventory_agent.py --agent-id ubuntu-vm --agent-token change-me --dashboard-url http://192.168.56.1:8000/api/agents/inventory/
sudo python3 ~/Desktop/victim_agent.py --agent-name ubuntu-vm --dashboard-url http://192.168.56.1:8000/api/alerts/ --packet-url http://192.168.56.1:8000/api/packets/

# 5. Removal
sudo python3 ~/Desktop/inventory_agent.py --uninstall-autostart
sudo python3 ~/Desktop/victim_agent.py --uninstall-autostart
```

---

## Token Authentication

Agents authenticate to the backend using an `AGENT_TOKEN` header:
- **Backend token** (`.env`): `AGENT_TOKEN=change-me`
- **Agent token** (env var): `export AGENT_TOKEN=change-me`

Both must match. If the backend receives a different token or no token when one is expected, it returns **HTTP 401**.

To disable token auth: Set `AGENT_TOKEN=""` in the `.env` file (token validation becomes optional).

The health endpoint also works as a simple SOC status check:

```bash
curl http://localhost:8000/api/agents/health/
```

It returns each agent’s `online` state, `last_seen`, and `offline_for_sec` value.

---

## ÉTAPE 4 — Attaquer depuis Kali

```bash
pip install scapy
sudo python agents/attacker.py
# Menu : 1=SYN Flood  2=ARP Spoof  3=ICMP Redirect
# Entrée pour stopper
```

---

## ÉTAPE 5 — Observer sur le dashboard

Ouvrir http://localhost:3000
→ Alertes en temps réel dans le feed
→ Métriques SYN/s, ARP anomalies
→ Export PDF depuis SessionReport

---

## Structure du projet

```
recon-tool/
├── agents/
│   ├── victim_agent.py     ← Copier sur Windows VM
│   └── attacker.py         ← Copier sur Kali VM
├── backend/
│   ├── scanner/
│   │   ├── discovery.py    ← ARP sweep
│   │   ├── portscan.py     ← SYN stealth + UDP
│   │   ├── fingerprint.py  ← OS fingerprint
│   │   ├── attacks.py      ← Attaques (côté serveur)
│   │   └── detection.py    ← Règles de détection
│   ├── api/views.py        ← 10 endpoints REST
│   ├── websockets/         ← Channels WebSocket
│   └── models.py           ← MongoDB documents
├── frontend/src/
│   ├── components/         ← NetworkMap, PortMatrix, etc.
│   └── hooks/              ← useWebSocket, useScan
├── docker-compose.yml
└── .env
```

---

## Commandes utiles

```bash
docker-compose up --build          # Lancer tout
docker-compose logs -f django      # Logs backend
docker-compose restart django      # Redémarrer backend
docker-compose down                # Arrêter
docker-compose down -v             # Arrêter + supprimer données
```

---

## Technologies

Scapy · Django 4.2 · Django Channels · MongoDB · React 18 · D3.js · ReportLab · Docker Compose

