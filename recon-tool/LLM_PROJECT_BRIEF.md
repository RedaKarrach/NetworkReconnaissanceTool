# Dossier LLM - Recon Tool (NIDS)

Ce document fournit un contexte complet et detaille pour qu un LLM comprenne le projet en profondeur sans devoir parcourir tout le depot. Il est volontairement exhaustif et structure par couche (reseau, agents, backend, frontend, persistance, runtime, stabilite).

## 1) Mission, perimetre et limites
Le projet est un NIDS (Network Intrusion Detection System) pedagogique. Il tourne exclusivement en laboratoire sur un reseau VirtualBox host-only. La finalite est de demontrer une chaine complete : generation de trafic, capture et detection, persistance, diffusion temps reel, visualisation SOC.

Objectifs majeurs:
- Supervision temps reel avec alertes et flux de paquets.
- Cartographie reseau, scan de ports, fingerprinting OS.
- Simulation d attaques en labo (SYN flood, ARP spoof, ICMP redirect).
- Inventaire d agents et suivi de leur sante.
- Deploiement reproductible via Docker Compose.

Limites explicites:
- Usage strictement labo (192.168.56.0/24 par defaut).
- Pas de durcissement production (auth faible, pas de chiffrement avance, couche Channels en memoire).
- Performances dimensionnees pour un petit lab, pas pour un trafic massif.

Contrainte de securite:
Ne jamais executer sur des reseaux tiers ou publics. Les attaques sont autorisees uniquement dans un environnement isole et controle.

## 2) Architecture globale
Vue logique:
- Machine hote (Windows) : Docker Compose, backend Django/Channels, frontend React, MongoDB.
- VM Kali : generation d attaques (attacker.py).
- VM Windows 10 (ou Ubuntu) : agent de detection + agent d inventaire.

Flux majeurs:
1) Scans/attaques/agents produisent des evenements (paquets, alertes, inventaires).
2) Backend persiste dans MongoDB (MongoEngine).
3) Backend diffuse en WebSocket vers le SOC.
4) Frontend consomme en temps reel (React + hooks).

Pipeline temps reel (simplifie):
Agent (VM) ou scanner (backend) -> API REST -> MongoDB -> Channels -> WebSocket -> UI.

## 3) Structure du depot
Arborescence principale:

recon-tool/
  backend/            Django, API, scanners, websockets, threads
  frontend/           React 18, Tailwind, pages SOC
  agents/             Scripts Python a deplacer sur les VMs
  docker-compose.yml  Orchestration Mongo + Django + React
Rapport/              Rapport academique detaille

## 4) Backend (Django + Channels)
Chemin: recon-tool/backend

Responsabilites:
- API REST pour scan, fingerprint, attaques, alertes, paquets, inventaires, rapports.
- Diffusion temps reel (Django Channels, WebSocket).
- Lancement d operations longues via threads (scan, attaques) sans bloquer le serveur.
- Persistance dans MongoDB via MongoEngine.

Modules cle:
- backend/api/views.py
  - Endpoints REST
  - Limites en memoire (caps) pour logs
  - Rate limiting sur l ingestion des paquets
- backend/scanner/
  - discovery.py: ARP sweep
  - portscan.py: SYN stealth + UDP
  - fingerprint.py: OS fingerprint
  - detection.py: regles de detection
  - attacks.py: attaques cote serveur
- backend/websockets/
  - consumers.py: diffusion temps reel
  - routing.py: routes WS
- backend/threads/manager.py
  - creation, suivi et arret des threads

### 4.1 Modèle de donnees (MongoEngine)
Chemin: backend/models.py

Documents principaux:
- ScanSession
  - Session de scan (pivot logique). Contient l identifiant de session, le reseau cible, et les timestamps.
- Host
  - Hote decouvert (IP, MAC, OS estime, etc.).
- PortResult
  - Resultats de scan par port (etat, service, banniere).
- Alert
  - Evenement de securite (type, severite, horodatage, contexte).
- PacketLog
  - Paquet capture (protocole, flags, TTL, src/dst, resume).
- AttackLog
  - Historique des attaques lancees depuis la console.
- HostInventory
  - Inventaire d hote envoye par inventory_agent.
- AgentRegistry
  - Enregistrement d agent (etat logique, dernier contact, metadata).

Les sessions servent de cle de correlation: hosts, ports, packets et alerts se rattachent a une session active.

### 4.2 API REST (familles)
Le backend expose des endpoints REST par famille fonctionnelle. Les chemins exacts se trouvent dans backend/api/urls.py et backend/api/views.py, mais la logique se regroupe ainsi:
- Decouverte et scan reseau: ARP discovery, scan TCP/UDP, fingerprint OS.
- Attaques cote serveur: lancement/arret des attaques ARP spoof, SYN flood, ICMP redirect.
- Ingestion d evenements: alerts et packet logs en provenance des agents.
- Inventaire et registre: inventaire d agent, inscription d agent, consultation d etat.
- Sessions et rapports: historique des resultats, export PDF de session.

### 4.3 WebSocket (temps reel)
Les consommateurs Channels diffusent:
- Alertes en temps reel.
- Flux de paquets.
- Mises a jour d inventaire et etat d agents.

La couche Channels utilise une couche en memoire (pas de Redis). Suffisant pour un lab mais pas pour une charge forte ou multi-nodes.

### 4.4 Gestion des threads
Les operations longues tournent dans des threads Python:
- Scan reseau.
- Scan de ports.
- Attaques cote serveur.

Un gestionnaire central garde l etat, l identifiant, et un event d arret. Cela permet d arreter proprement via l UI ou l API.

## 5) Frontend (React 18)
Chemin: recon-tool/frontend/src

Responsabilites:
- Tableaux de bord SOC, alertes temps reel.
- Cartographie reseau D3.js.
- Packet inspector en live.
- Panneau OS fingerprint.
- Console d attaques et rapport de session.
- Pages Endpoints et Inventory.

Points d entree:
- src/index.js, src/App.jsx
- src/pages/ (Dashboard, SOCDashboard, Inventory, Endpoints, Login, LoginPage)
- src/components/ (NetworkMap, PortMatrix, PacketInspector, AttackConsole, SessionReport, etc.)
- src/hooks/ (useWebSocket, useScan, useInventory, useAgentHealth, useAgentRegistry)

Fonctionnement general:
- Les hooks abonnent l UI aux flux WS.
- Les pages orchestrent le rendu et appellent les endpoints REST.
- Les composants de visualisation (D3, charts) reçoivent des donnees normalisees et filtrees.

## 6) Agents (scripts Python, VMs)
Chemin: recon-tool/agents

### 6.1 victim_agent.py (Windows VM)
Role:
- Sniffe le trafic local (Scapy + Npcap).
- Detecte anomalies (ARP, SYN flood).
- Envoie alertes et paquets au backend (HTTP POST).

### 6.2 ubuntu_victim_agent.py (Ubuntu VM)
Role:
- Meme logique que victim_agent.py mais adapte a Linux.

### 6.3 attacker.py (Kali VM)
Role:
- Lance des attaques de laboratoire:
  - SYN flood
  - ARP spoof
  - ICMP redirect

### 6.4 inventory_agent.py (Windows/Kali/Ubuntu)
Role:
- Envoie un inventaire periodique de l hote (CPU, RAM, OS, interfaces, etc.).
- Sert aussi de heartbeat pour le statut online/offline.

### 6.5 Authentification agent
Optionnelle via entete AGENT_TOKEN.
- Backend: variable AGENT_TOKEN (via .env).
- Agent: variable AGENT_TOKEN (env).
Si mismatch: HTTP 401.

## 7) Regles de detection
Implantees (backend/scanner/detection.py + agents):
- ARP anomaly: changement de MAC pour une IP connue.
- Port sweep: trop de ports distincts dans une fenetre de temps.
- SYN flood: taux anormal de SYN vers une cible.

Evolutions mentionnees (pas fully implantees):
- Detection ICMP redirect non sollicite.
- Detection d anomalies via ML.

## 8) Deploiement et reseau laboratoire
Reseau host-only VirtualBox:
- vboxnet0: 192.168.56.1/24 (host)
- Kali: 192.168.56.10
- Windows victime: 192.168.56.20
- Ubuntu optionnel: 192.168.56.30

Demarrage stack (host):
- Dans recon-tool/ : docker-compose up --build
- Frontend: http://localhost:3000
- API: http://localhost:8000/api/

Prerequis agents:
- Windows: Npcap obligatoire pour sniffing Scapy.
- Linux: scapy, requests, psutil via pip3.

## 9) Stabilite et performances
Reference: recon-tool/STABILITY_TUNING.md

Mesures implementees:
- TTL index MongoDB (expiration automatique, 30 jours par defaut).
- Caps en memoire sur PacketLog et Alert par session.
- Rate limiting sur ingestion des packets (packets/sec).
- Throttling de l attaquant (SYN_FLOOD_PPS).
- Limites CPU/RAM des containers via Docker Compose.

Effet attendu:
- Evite la croissance illimitee des collections.
- Maintient l UI reactive pendant des attaques simulees.

## 10) Fonctionnement detaille par scenarios
### 10.1 Decouverte reseau
- L utilisateur lance un ARP sweep.
- Le backend envoie des requetes ARP via Scapy.
- Les reponses alimentent Host et sont diffusees en temps reel.
- NetworkMap affiche les noeuds en direct.

### 10.2 Scan de ports
- L utilisateur declenche un scan TCP/UDP.
- Le backend envoie des SYN stealth et probe UDP.
- Les resultats sont persistés (PortResult).
- PortMatrix et SessionReport s actualisent.

### 10.3 Fingerprinting OS
- Le backend collecte TTL, fenetre TCP et reponse Xmas.
- Il combine ces indices pour estimer l OS.
- L OSFingerprintPanel affiche une estimation et son contexte.

### 10.4 Attaque ARP spoof
- L attaqueur (Kali) lance ARP spoof.
- Victim agent detecte incoherence IP/MAC.
- Une alerte de severite elevee remonte au SOC.

### 10.5 SYN flood
- L attaqueur lance un flood (PPS limite par config).
- Victim agent detecte un taux SYN anormal.
- Le backend emet une alerte critique, PacketInspector sature visuellement.

### 10.6 Inventaire et sante agents
- Inventory agent envoie un heartbeat periodique.
- Backend marque online/offline selon last_seen.
- Le SOC affiche les agents et leurs metadonnees.

## 11) Points d entree et fichiers de reference
Pour details exacts (endpoints, schemas, params):
- recon-tool/README.md
- recon-tool/README_VM_SCRIPTS.md
- recon-tool/STABILITY_TUNING.md
- Rapport/rapport_pfa.md

## 12) Resume mental complet
Le systeme est une boucle fermee de supervision:
- Generation de trafic (attaques + scans)
- Observation et detection (agents + backend)
- Persistance et diffusion (MongoDB + Channels)
- Visualisation et reporting (React SOC)

Ce dossier est concu pour fournir un contexte maximal a un LLM en phase d analyse ou de generation de code/documentation.

## 13) API REST - liste exhaustive et schemas
Base: http://<host>:8000/api/
Toutes les reponses sont JSON (sauf PDF).

### 13.1 Scan et fingerprint
POST scan/host-discovery/
- Body:
  { "subnet": "192.168.56.0/24" }
- Reponse 202:
  { "session_id", "thread_id", "subnet", "status":"running" }
- Effets: cree ScanSession, enregistre Host, diffuse packets/alerts, journalise audit.
- Erreurs: 400 si subnet manquant.

POST scan/port-scan/
- Body:
  { "ip": "192.168.56.20", "ports": [22,80], "protocol": "tcp" }
- Reponse 202:
  { "session_id", "thread_id", "ip", "protocol", "port_count", "status":"running" }
- Effets: cree ScanSession, Host, PortResult, emits alerts (scan start/complete, nmap_like), calcule risk score.
- Erreurs: 400 ip manquant, 400 ip hors subnet autorise, 404 ip unreachable.

POST scan/os-fingerprint/
- Body:
  { "ip": "192.168.56.20" }
- Reponse 202:
  { "session_id", "thread_id", "ip", "status":"running" }
- Effets: cree ScanSession, met a jour Host (os_guess/confidence), diffuse packet "os_result".
- Erreurs: 400 ip manquant, 400 ip hors subnet autorise, 404 ip unreachable.

### 13.2 Attaques (cote serveur)
POST attack/arp-spoof/
- Body:
  { "target_ip": "192.168.56.20", "gateway_ip": "192.168.56.1" }
- Reponse 202:
  { "session_id", "thread_id", "target_ip", "gateway_ip", "status":"running" }
- Effets: AttackLog, packet logs, alert "arp_spoof".
- Erreurs: 400 si target_ip/gateway_ip manquant.

POST attack/syn-flood/
- Body:
  { "target_ip": "192.168.56.20", "target_port": 80 }
- Reponse 202:
  { "session_id", "thread_id", "target_ip", "target_port", "status":"running" }
- Effets: AttackLog, packet logs, alert "syn_flood", detection syn_flood.
- Erreurs: 400 si target_ip manquant.

POST attack/icmp-redirect/
- Body:
  { "target_ip", "spoofed_gateway", "attacker_ip", "destination_ip" }
- Reponse 202:
  { "session_id", "thread_id", "target_ip", "spoofed_gateway", "attacker_ip", "destination_ip", "status":"running" }
- Effets: AttackLog, packet logs, alert "icmp_redirect".
- Erreurs: 400 si champs requis manquants.
- Note: route exposee seulement si ICMPRedirectView importable.

POST attack/stop/
- Body:
  { "thread_id": "..." }
- Reponse 200:
  { "thread_id", "stopped": true|false }
- Effets: stop thread via manager.
- Erreurs: 400 si thread_id manquant.

GET threads/
- Reponse 200:
  { "items": [ { "thread_id", "name", "alive", "status", "meta" } ] }

GET threads/<thread_id>/
- Reponse 200: objet status thread.
- Erreurs: 404 si thread introuvable.

### 13.3 Ingestion agents (alerts + packets)
POST alerts/
- Body:
  { "agent", "type", "src_ip", "dst_ip", "severity", "message" }
- Reponse 201:
  { "status":"ok", "session_id", "alert_id" }
- Effets: cree Alert, diffuse en WS, peut recalculer risk score.

POST packets/
- Body:
  { "summary", "flags", "ttl", "src_ip", "dst_ip", "protocol", "timestamp" }
- Reponse 201:
  { "status":"ok" }
- Effets: cree PacketLog, detections passives (ARP/SYN/port sweep/ICMP), diffuse en WS.
- Erreurs: 429 si rate limit atteint.

### 13.4 Historique
GET alerts/history/<session_id>/?limit=200
- Reponse 200:
  { "items": [ { "type", "src_ip", "dst_ip", "severity", "message", "timestamp" } ] }

GET packets/history/<session_id>/?limit=500
- Reponse 200:
  { "items": [ { "summary", "flags", "ttl", "src_ip", "dst_ip", "protocol", "timestamp" } ] }

### 13.5 Inventaire et registre agents
POST agents/inventory/
- Auth optionnelle: X-AGENT-TOKEN ou Authorization: Bearer <token>
- Body principal:
  { "agent_id", "hostname", "os_name", "os_version", "kernel", "arch", "domain",
    "ips":[], "macs":[], "interfaces":[], "cpu_model", "cpu_cores", "ram_mb",
    "disk_total_gb", "disk_free_gb", "uptime_sec", "users":[], "packages":[],
    "services":[], "open_ports":[] }
- Reponse 201:
  { "status":"ok", "agent_id" }
- Effets: upsert HostInventory, upsert AgentRegistry, broadcast inventory, alert agent_online si nouveau.
- Erreurs: 401 si token invalide, 400 si agent_id/hostname manquant.

DELETE agents/inventory/
- Body:
  { "agent_id" | "hostname" | "ip" }
- Reponse 200:
  { "status":"deleted", "agent_id" }
- Effets: supprime HostInventory + AgentRegistry associe, broadcast inventory_deleted.
- Erreurs: 401 si token invalide, 404 si non trouve.

GET agents/inventory/latest/?limit=50
- Reponse 200:
  { "items": [ inventory fields + last_seen ] }

GET agents/registry/
- Reponse 200:
  { "items": [ { "agent_id", "hostname", "ip", "os_name", "notes", "last_seen", "health_status", "health_notified_at", "created_at" } ] }

POST agents/registry/
- Body:
  { "agent_id", "hostname", "ip", "os_name", "notes" }
- Reponse 201:
  { "status":"ok", "agent_id" }
- Erreurs: 409 si agent_id ou ip deja existant.

DELETE agents/registry/
- Body:
  { "agent_id" | "ip" }
- Reponse 200:
  { "status":"deleted" }
- Erreurs: 404 si non trouve.

GET agents/health/?limit=200
- Reponse 200:
  { "items": [ { "agent_id", "hostname", "ip", "os_name", "last_seen", "health_status", "online", "offline_for_sec" } ],
    "offline_threshold_sec", "generated_at" }

### 13.6 Resultats, risk score, audit et MITRE
GET results/<session_id>/
- Reponse 200:
  { "session_id", "subnet", "status", "timestamp", "hosts": [ { "ip", "mac", "os_guess", "confidence", "ports": [ {"port","protocol","status","banner"} ] } ],
    "alerts": [ {"type","src_ip","dst_ip","severity","message","timestamp"} ],
    "packet_count" }

GET report/<session_id>/pdf/
- Reponse 200: PDF (attachment).

GET hosts/<ip>/risk-score/
- Reponse 200:
  { "ip", "risk_score", "risk_level", "breakdown": { "risky_ports":[], "vulns":[], "failed_logins":0 } }

GET audit-logs/?limit=100&offset=0&action=scan_started&hours=24
- Reponse 200:
  { "count", "results": [ { "action", "initiated_by", "initiated_at", "status", "duration_ms", "detail", "error_message" } ] }

GET mitre-mapping/
- Reponse 200: mapping MITRE issu de scanner/detection.

## 14) WebSocket (temps reel)
Route: ws/scan/<session_id>/
- session_id peut etre "live" pour le flux global SOC.
- Le serveur emet des messages "packet", "alert" et "status" selon les actions en cours.

## 15) Procedure d execution detaillee (lab)
### 15.1 Pre-requis
- VirtualBox avec reseau host-only (vboxnet0, 192.168.56.1/24).
- 1 VM Kali (attaquant) + 1 VM Windows 10 (victime). Optionnel: Ubuntu.
- Docker Desktop sur la machine hote.
- Python + pip sur les VMs.

### 15.2 Configuration reseau VirtualBox
1) VirtualBox > Gestionnaire de reseau host-only
   - IPv4: 192.168.56.1 / 255.255.255.0
   - DHCP: active
2) Adapter chaque VM sur vboxnet0.
3) Fixer les IP:
   - Kali: 192.168.56.10
   - Windows: 192.168.56.20
   - Ubuntu: 192.168.56.30 (optionnel)

### 15.3 Lancer le SOC (machine hote)
Dans recon-tool/:
- docker-compose up --build
Verifier:
- http://localhost:3000 (frontend)
- http://localhost:8000/api/ (backend)

### 15.4 Installer et lancer les agents (VMs)
Windows 10:
1) Installer Npcap.
2) pip install scapy requests psutil
3) Lancer victim_agent.py en admin.
4) Lancer inventory_agent.py (optionnel mais recommande).

Ubuntu:
1) pip3 install scapy requests psutil
2) Lancer ubuntu_victim_agent.py (sudo).
3) Lancer inventory_agent.py (optionnel).

Kali:
1) pip3 install scapy requests psutil
2) Lancer attacker.py (sudo).

### 15.5 Verifications rapides
- API health agents: GET /api/agents/health/
- Les alertes apparaissent dans le flux SOC.
- PacketInspector recoit les events en live.

### 15.6 Scenario demo minimal
1) Host discovery (scan/host-discovery).
2) Port scan sur une IP detectee.
3) OS fingerprint sur la meme IP.
4) Lancer SYN flood depuis Kali.
5) Observer alertes + paquets + SessionReport.

### 15.7 Arret propre
- Stopper attaques via POST /api/attack/stop/ avec thread_id.
- docker-compose down pour tout arreter.

## 16) Notes d exploitation et contraintes
- Le backend limite les paquets par session (rate limit) et coupe les logs a des seuils fixes.
- L absence de Redis signifie que les WS ne sont pas partagees entre plusieurs instances.
- Si les VMs changent d IP, mettre a jour les scripts agents.