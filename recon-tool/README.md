# Network Intrusion Detection System (NIDS)
## Projet de Fin d'Études — EMSI 4CIRG1

> ⚠️  LAB UNIQUEMENT — réseau VirtualBox isolé, jamais sur un réseau tiers.

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

## ÉTAPE 3 — Agent victime (Windows VM)

```powershell
# 1. Installer Npcap : https://npcap.com
# 2. Installer deps
pip install scapy requests
# 3. Lancer (PowerShell Admin)
python agents/victim_agent.py
```

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

*EMSI 4CIRG1 — 2024/2025*
