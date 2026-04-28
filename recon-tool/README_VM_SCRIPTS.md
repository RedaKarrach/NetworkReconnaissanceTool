# Scripts de lancement par VM (avec tes chemins)

Ce guide te donne les scripts exacts a lancer pour chaque machine du labo.

## 1) Chemins source sur ta machine hote (Windows)

Ces fichiers existent dans ton projet:

- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\attacker.py`
- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\victim_agent.py`
- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\inventory_agent.py`

## 2) Script machine hote (SOC) a lancer d abord

PowerShell (machine hote):

```powershell
Set-Location "C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool"
docker-compose up -d mongo django react
docker-compose ps
```

Le backend/API doit etre accessible sur `http://192.168.56.1:8000`.

## 3) VM Windows 10 (victime)

### 3.1 Preparation (PowerShell Admin)

```powershell
# Installer Python deps
py -m pip install --upgrade pip
py -m pip install scapy requests psutil

# IMPORTANT: installer Npcap manuellement si absent
# https://npcap.com
```

### 3.2 Copier les scripts sur la VM Windows

Copie depuis la machine hote vers la VM (via dossier partage / USB / reseau) ces fichiers source:

- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\victim_agent.py`
- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\inventory_agent.py`

Exemple destination sur ta VM Windows:

- `C:\Users\reda\Desktop\victim_agent.py`
- `C:\Users\reda\Desktop\inventory_agent.py`

### 3.3 Lancer la detection victime

Terminal PowerShell Admin #1:

```powershell
$env:PYTHONUNBUFFERED="1"
py C:\Users\reda\Desktop\victim_agent.py
```

### 3.4 Lancer l inventaire (optionnel mais recommande)

Terminal PowerShell Admin #2:

```powershell
$env:DASHBOARD_URL="http://192.168.56.1:8000/api/agents/inventory/"
$env:AGENT_ID="win-victim"
$env:AGENT_TOKEN=""
$env:INTERVAL="60"
py C:\Users\reda\Desktop\inventory_agent.py
```

## 4) VM Kali Linux (attaquant)

### 4.1 Preparation

```bash
sudo apt update
sudo apt install -y python3-pip
python3 -m pip install --upgrade pip
python3 -m pip install scapy requests psutil
```

### 4.2 Copier les scripts sur la VM Kali

Copie depuis la machine hote:

- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\attacker.py`
- `C:\Users\redan\OneDrive\Bureau\NetworkToolPFA\recon-tool\agents\inventory_agent.py`

Exemple destination sur Kali:

- `/home/kali/recon-agents/attacker.py`
- `/home/kali/recon-agents/inventory_agent.py`

### 4.3 Lancer l attaque

```bash
sudo -E python3 /home/kali/recon-agents/attacker.py
```

Le menu propose:

- `1` SYN Flood
- `2` ARP Spoofing
- `3` ICMP Redirect

### 4.4 Lancer l inventaire Kali (optionnel)

```bash
export DASHBOARD_URL="http://192.168.56.1:8000/api/agents/inventory/"
export AGENT_ID="kali-attacker"
export AGENT_TOKEN=""
export INTERVAL="60"
python3 /home/kali/recon-agents/inventory_agent.py
```

## 5) Verifications rapides

- Dashboard front: `http://localhost:3000`
- API host-only: `http://192.168.56.1:8000/api/`
- Si les alertes ne remontent pas: verifier IP host-only, pare-feu Windows VM, Npcap, et droits admin/root.

## 6) Notes importantes

- Usage strictement labo isole (`192.168.56.0/24`).
- Les attaques doivent rester dans un environnement autorise.
- Si tu changes les IP VM, adapte les constantes dans `attacker.py` et `victim_agent.py`.
