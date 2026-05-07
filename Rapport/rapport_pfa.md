<!-- PAGE DE GARDE -->
<div align="center">

[LOGO EMSI À INSÉRER ICI]

<br><br>

**ÉCOLE MAROCAINE DES SCIENCES DE L’INGÉNIEUR**

**Projet de Fin d’Année**

**Filière : Ingénierie Informatique et Réseaux**

<br>

# Rapport de Projet de Fin d’Année

## Système de Détection d’Intrusions Réseau en Temps Réel

<br><br>

**Réalisé par :**

Nom Prénom 1

Nom Prénom 2

<br>

**Encadré par :**

Nom de l’encadrant académique

<br><br>

**Année universitaire 2024–2025**

</div>

<div style="page-break-after: always;"></div>

# Remerciements

Ce projet de fin d’année, mené dans le cadre de notre formation à l’EMSI, a constitué une étape exigeante et formatrice. Il n’aurait pu être conduit à son terme sans l’appui de plusieurs personnes que nous tenons à remercier sincèrement.

Nous adressons d’abord nos remerciements à notre encadrant académique pour la précision de ses remarques, la rigueur de sa méthode et la pertinence de ses orientations techniques. Ses conseils nous ont aidés à structurer notre démarche, à hiérarchiser les priorités du projet et à conserver une cohérence entre la partie réseau, la partie détection et l’interface de supervision. Sa disponibilité tout au long du travail a été décisive pour faire évoluer nos choix avec discernement.

Nous remercions également l’ensemble des enseignants de l’EMSI pour la solidité des bases théoriques transmises durant l’année. Les enseignements en réseaux, programmation système, développement web, bases de données et cybersécurité ont directement nourri la conception de notre plateforme. Ce projet nous a permis de mobiliser ces acquis de manière transversale et concrète, dans une logique d’intégration de compétences.

Enfin, nous exprimons notre reconnaissance à nos familles et à nos proches pour leur soutien constant durant cette période de travail soutenu. Leur présence et leurs encouragements nous ont permis de maintenir la concentration nécessaire pour mener à bien les phases de développement, de test et de rédaction.

# Résumé

Ce rapport présente la conception et la réalisation d’un système de détection d’intrusions réseau en temps réel développé dans le cadre d’un Projet de Fin d’Année à l’EMSI. Le projet repose sur une architecture distribuée déployée dans un laboratoire VirtualBox isolé : une machine hôte exécute la supervision conteneurisée, une VM Kali Linux joue le rôle d’attaquant et une VM Windows 10 héberge l’agent de détection et l’agent d’inventaire. Le cœur technique s’appuie sur Scapy pour la découverte d’hôtes par ARP, le scan de ports en SYN stealth, le fingerprinting du système d’exploitation à partir de signaux réseau et la génération de plusieurs scénarios d’attaque. Le backend Django 4.2 expose une API REST, persiste les événements dans MongoDB via MongoEngine et diffuse les alertes en temps réel avec Django Channels et une couche de canal en mémoire. Le frontend React 18 fournit un tableau de bord SOC moderne comprenant une carte réseau interactive en D3.js, une matrice de ports, un inspecteur de paquets, un panneau de fingerprinting, une console d’attaque, un module de rapport de session et des vues d’inventaire et d’enregistrement des agents. L’ensemble est orchestré par Docker Compose afin de garantir un environnement reproductible et portable. Le projet met en évidence la cohérence d’une chaîne complète allant de la capture réseau à la visualisation opérationnelle, tout en restant adaptée à un cadre pédagogique de laboratoire.

# Abstract

This report describes the design and implementation of a real-time network intrusion detection system developed as a final-year project at EMSI. The solution is built around a distributed architecture deployed in an isolated VirtualBox laboratory: a host machine runs the containerized supervision stack, a Kali Linux VM acts as the attacker, and a Windows 10 VM hosts the detection agent and the inventory agent. The technical core relies on Scapy for ARP host discovery, TCP SYN stealth port scanning, operating system fingerprinting based on network responses, and attack simulation. The backend is implemented with Django 4.2, exposes a REST API, persists events in MongoDB through MongoEngine, and broadcasts live alerts with Django Channels using an in-memory channel layer. The frontend is developed with React 18 and provides a modern SOC dashboard featuring an interactive D3.js network graph, a port matrix, a live packet inspector, an OS fingerprinting panel, an attack console, a session report module, and endpoint and inventory views. Docker Compose orchestrates the full stack and makes the laboratory reproducible with minimal setup. The project demonstrates a complete workflow from packet capture to operational visualization, while remaining intentionally lightweight and fully suited to an academic lab environment. Beyond the implemented features, the architecture also leaves room for future extensions such as stronger authentication, encrypted transport, and more advanced anomaly-based detection.

# Liste des Abréviations

| Abréviation | Signification |
|-------------|---------------|
| API | Application Programming Interface |
| ARP | Address Resolution Protocol |
| ASGI | Asynchronous Server Gateway Interface |
| CVE | Common Vulnerabilities and Exposures |
| CPU | Central Processing Unit |
| D3 | Data-Driven Documents |
| DRF | Django REST Framework |
| HTTP | Hypertext Transfer Protocol |
| HTTPS | Hypertext Transfer Protocol Secure |
| ICMP | Internet Control Message Protocol |
| IDS | Intrusion Detection System |
| IP | Internet Protocol |
| MAC | Media Access Control |
| ML | Machine Learning |
| NIDS | Network Intrusion Detection System |
| OS | Operating System |
| PFA | Projet de Fin d’Année |
| PDF | Portable Document Format |
| REST | Representational State Transfer |
| RAM | Random Access Memory |
| SOC | Security Operations Center |
| SYN | Synchronize (flag TCP) |
| TCP | Transmission Control Protocol |
| TTL | Time To Live |
| UDP | User Datagram Protocol |
| VM | Virtual Machine |
| WS | WebSocket |
| WSGI | Web Server Gateway Interface |

# Introduction générale

La circulation massive des données dans les réseaux modernes rend la détection des activités malveillantes particulièrement stratégique. Les attaques par saturation, les manipulations de protocoles de résolution d’adresses et les tentatives de redirection de trafic exploitent des mécanismes réseau fondamentaux, ce qui les rend à la fois simples à déclencher et difficiles à distinguer d’un trafic légitime sans supervision adaptée. Dans ce contexte, un système de détection d’intrusions en temps réel constitue un outil essentiel pour observer, comprendre et documenter les comportements suspects.

Les solutions existantes répondent souvent à une partie seulement du besoin. Certaines se concentrent sur l’analyse de signatures, d’autres sur la collecte de journaux ou l’observabilité, mais peu offrent une chaîne pédagogique complète reliant génération d’attaque, détection, persistance et visualisation dans une interface unifiée. C’est précisément cette continuité que nous avons cherchée à construire, afin de disposer d’un environnement à la fois démonstratif, modulaire et exploitable dans le cadre d’un laboratoire académique.

Notre projet consiste donc à concevoir un NIDS distribué déployé dans un réseau VirtualBox isolé. La partie détection s’appuie sur Scapy pour la capture et l’analyse des paquets, le backend Django expose les services métiers et la diffusion temps réel, tandis que le frontend React fournit un SOC interactif orienté analyse. Cette séparation en couches nous a permis de garder chaque responsabilité clairement identifiée, tout en maintenant une cohérence forte entre la capture, la détection et l’affichage.

Le rapport est organisé en cinq chapitres. Le premier présente les besoins, l’architecture globale et les choix technologiques. Le deuxième décrit l’implémentation réseau, les scans et les mécanismes de détection. Le troisième détaille le backend, la pipeline temps réel et le déploiement. Le quatrième est consacré à l’interface SOC et aux composants frontend. Le cinquième rassemble les tests, les résultats observables et les perspectives d’évolution.

# Chapitre 1 — Analyse des besoins et conception

Ce premier chapitre pose le cadre du projet et précise les motivations qui ont guidé sa conception. Nous y présentons la problématique, l’état de l’art de manière comparative, l’architecture générale retenue, les technologies choisies et le modèle de données qui structure la persistance.

## 1.1 Problématique et objectifs

La difficulté principale d’un laboratoire de détection d’intrusions ne réside pas seulement dans la capacité à observer du trafic réseau, mais dans la continuité entre l’attaque, l’analyse et la restitution visuelle. Dans de nombreux environnements pédagogiques, les captures sont traitées a posteriori, ce qui rompt le lien temporel entre l’événement et sa détection. Nous avons donc cherché à construire une plateforme capable d’absorber les paquets, de déclencher des alertes et de les afficher immédiatement dans une interface de supervision.

Notre objectif était de concevoir une solution intégrée, légère et reproductible, sans dépendre d’une infrastructure lourde. Nous voulions disposer d’un moteur de reconnaissance réseau, d’un système d’alerte en temps réel, d’un tableau de bord SOC moderne et d’un agent d’inventaire capable d’enrichir la vue opérationnelle. L’ensemble devait fonctionner dans un laboratoire isolé afin d’éviter tout impact sur des réseaux tiers.

L’intérêt pédagogique de cette approche est important, car elle permet de suivre la chaîne complète de détection, depuis le paquet brut jusqu’à son interprétation dans l’interface. En conservant la maîtrise du code à chaque niveau, nous avons pu comprendre les interactions entre capture réseau, diffusion asynchrone, stockage et visualisation. Cette transparence architecturale constitue un choix volontaire, plus adapté à un projet académique qu’une solution encapsulée difficile à auditer.

## 1.2 Analyse de l’existant

Afin de situer notre travail, nous avons comparé la solution développée avec trois outils de référence souvent cités dans le domaine de la supervision réseau. Le tableau suivant met en évidence les différences de couverture fonctionnelle.

| Critère | Wazuh | Snort | Wireshark | Notre NIDS |
|---------|-------|-------|-----------|------------|
| Détection temps réel | Oui | Oui | Non | Oui |
| Tableau de bord SOC | Partiel | Non | Non | Oui |
| Génération d’attaques intégrée | Non | Non | Non | Oui |
| Découverte réseau | Partielle | Non | Non | Oui |
| Fingerprinting OS | Non | Partiel | Non | Oui |
| Inventaire des agents | Oui | Non | Non | Oui |
| Déploiement reproductible | Oui | Partiel | Non | Oui |
| Visée pédagogique | Moyenne | Moyenne | Forte | Très forte |

Wazuh offre une supervision large, mais sa mise en place suppose une chaîne d’outils plus lourde et moins transparente pour un étudiant qui souhaite comprendre les mécanismes internes. Snort reste une référence en matière de détection par signatures, toutefois il ne propose pas une expérience de visualisation aussi intégrée. Wireshark, quant à lui, excelle dans l’analyse forensique, mais il ne répond pas à l’exigence d’alerte automatique et de corrélation en temps réel. Notre proposition se distingue donc par l’intégration de la capture, de l’alerte, du SOC et de la simulation d’attaque dans un même environnement contrôlé.

Cette comparaison montre que notre NIDS n’ambitionne pas de remplacer des solutions industrielles matures, mais d’offrir une plateforme cohérente pour démontrer les mécanismes essentiels de la détection réseau. L’équilibre recherché est celui d’un outil complet, lisible et facile à déployer. Le choix d’un périmètre plus restreint permet en outre de conserver la clarté du code et la traçabilité des événements.

## 1.3 Architecture globale

L’architecture du système repose sur un réseau VirtualBox Host-Only isolé, utilisé comme laboratoire de test. Trois rôles principaux y coexistent : la machine hôte qui exécute les services conteneurisés de supervision, la VM Kali Linux qui génère les attaques et la VM Windows 10 qui reçoit les paquets, exécute l’agent de détection et remonte les alertes. Cette séparation des responsabilités reproduit fidèlement une chaîne de supervision réaliste tout en restant maîtrisable.

La figure 1 ci-dessous illustre cette organisation générale.

[FIGURE 1 — Architecture globale du système : machine hôte exécutant Docker Compose, VM Kali Linux lançant les attaques et VM Windows 10 hébergeant l’agent de détection et l’agent d’inventaire.]

On peut observer que la circulation des flux est volontairement asymétrique. Les attaques partent de la VM Kali vers la VM victime ou vers la passerelle du laboratoire, tandis que les alertes et les métriques remontent vers la machine hôte. Cette logique de séparation est essentielle, car elle évite de confondre la source de l’attaque avec la source de supervision. Elle facilite également les tests, puisque chaque rôle peut être lancé et observé indépendamment.

Le choix d’un réseau Host-Only garantit que le trafic reste confiné au laboratoire. Aucun paquet n’est exposé vers un réseau externe, ce qui limite les risques opérationnels et juridiques. Cette isolation nous a permis de simuler des scénarios agressifs comme le SYN flood ou l’ARP spoofing sans sortir du cadre académique.

La figure 2 ci-dessous présente la configuration réseau de VirtualBox utilisée pour le laboratoire.

[FIGURE 2 — Configuration VirtualBox Host-Only : interface vboxnet0, adresse 192.168.56.1 et masque 255.255.255.0, avec VM connectées au réseau isolé.]

On remarque que l’adressage privé en 192.168.56.0/24 structure l’ensemble du laboratoire. Cette plage facilite la documentation, les tests et la normalisation des configurations IP sur les différentes machines. Elle crée également une base stable pour la supervision, puisque les adresses critiques restent constantes d’une session à l’autre.

## 1.4 Choix technologiques

Les technologies retenues ont été sélectionnées pour leur simplicité d’intégration, leur stabilité et leur compatibilité avec un environnement pédagogique. Nous avons privilégié des composants éprouvés, capables de fonctionner ensemble sans imposer une infrastructure externe trop lourde. Le tableau suivant synthétise les principaux choix.

| Couche | Technologie | Justification |
|--------|-------------|---------------|
| Capture et injection réseau | Scapy | Accès direct aux couches 2 et 3, API Python cohérente, forte souplesse |
| Backend applicatif | Django 4.2.9 | Structure robuste, administration intégrée, maturité du framework |
| API | Django REST Framework | Sérialisation simple, endpoints lisibles, intégration naturelle avec Django |
| Temps réel | Django Channels 4.0.0 | Support WebSocket natif dans l’écosystème Django |
| Base de données | MongoDB + MongoEngine | Schéma souple pour des métadonnées réseau hétérogènes |
| Tâches d’exécution | Threads Python | Simplicité, contrôle fin de l’arrêt, absence de broker externe |
| Frontend | React 18 + TailwindCSS | Composants réactifs et interface modulable |
| Visualisation réseau | D3.js | Graphe force-directed interactif et adaptable |
| Graphiques | Recharts | Intégration naturelle avec React pour les tableaux de bord |
| Déploiement | Docker Compose | Reproductibilité et séparation claire des services |
| Export documentaire | ReportLab | Génération simple d’un PDF de synthèse |

Le choix de Scapy est central, car il permet à la fois la création et l’analyse de paquets au sein du même langage. Contrairement à une architecture qui séparerait capture, génération et traitement dans des outils différents, nous avons préféré une approche homogène, plus facile à maintenir. Cette cohérence réduit la friction entre les modules et accélère la compréhension du code.

Le backend repose sur Django plutôt que sur un microservice plus minimaliste, car nous avions besoin d’une base solide pour l’API, l’administration et la persistance. Django Channels permet de compléter cette structure avec des WebSocket sans introduire de broker externe. Enfin, le choix d’une couche de canal en mémoire simplifie le déploiement et reste adapté au débit d’un laboratoire de taille réduite.

## 1.5 Modèle de données

Le modèle de données du projet est organisé autour de documents MongoEngine qui structurent les événements réseau, les sessions et les inventaires d’agents. Contrairement à un schéma relationnel rigide, ce choix permet d’absorber des objets aux attributs variables selon le protocole, la session ou le type d’événement. Cette flexibilité est particulièrement utile pour des métadonnées réseau hétérogènes.

Le document `ScanSession` sert de racine logique à chaque campagne. Il enregistre l’identifiant de session, le sous-réseau ciblé, l’état courant et un horodatage de création. Les documents `Host`, `PortResult`, `Alert` et `PacketLog` s’y rattachent pour préserver la cohérence des données. Le document `AttackLog` conserve l’historique des attaques lancées depuis la console, tandis que `HostInventory` et `AgentRegistry` gèrent respectivement l’inventaire remonté par les machines et leur enregistrement manuel dans l’interface.

Ce modèle montre que le projet ne se limite pas à la détection brute. Il conserve aussi les traces nécessaires à l’analyse, au rapport de session et au suivi des agents. En pratique, cette structure autorise une vue globale : quels hôtes ont été découverts, quels ports sont ouverts, quelles alertes ont été générées et quels agents ont récemment communiqué avec la plateforme.

La figure 3 ci-dessous illustre le rôle du modèle de données dans la chaîne de supervision.

[FIGURE 3 — Schéma conceptuel des documents MongoEngine : ScanSession, Host, PortResult, Alert, PacketLog, AttackLog, HostInventory et AgentRegistry reliés par les identifiants de session et d’agent.]

On peut observer que la session joue un rôle de pivot transversal. Elle garantit l’isolation entre différentes campagnes de test et simplifie la génération de rapports. Cette organisation est plus lisible qu’un stockage dispersé, car elle permet de reconstruire rapidement le contexte d’un événement particulier.

# Chapitre 2 — Implémentation technique

Ce chapitre décrit le cœur opérationnel du projet. Nous y détaillons la découverte réseau, le scan de ports, le fingerprinting des systèmes d’exploitation, les mécanismes de détection et le rôle de l’agent de détection installé sur la machine victime.

## 2.1 Découverte réseau

La découverte d’hôtes repose sur un balayage ARP réalisé avec Scapy. Le principe est simple : l’agent envoie des requêtes ARP en broadcast sur le sous-réseau ciblé, puis collecte les réponses des machines actives. Cette méthode fonctionne au niveau liaison et permet de détecter rapidement les hôtes présents sans nécessiter de connexion TCP préalable.

Dans notre implémentation, chaque réponse ARP est transformée en enregistrement d’hôte, puis persistée dans MongoDB et diffusée vers les clients WebSocket. Cette double action est importante : elle conserve une trace historique tout en alimentant immédiatement l’interface graphique. Le composant NetworkMap exploite ensuite ces données pour dessiner une topologie interactive.

La figure 4 ci-dessous montre la logique de découverte réseau.

[FIGURE 4 — Capture de la découverte ARP : requêtes broadcast envoyées sur 192.168.56.0/24 et hôtes répondant avec leur adresse MAC.]

On peut observer que la découverte repose sur une mécanique très directe et fiable dans un laboratoire isolé. La simplicité du protocole ARP en fait un excellent point d’entrée pour expliquer la cartographie réseau. Elle facilite aussi la compréhension des interactions entre niveau 2 et niveau applicatif.

## 2.2 Scan de ports

Le scan de ports est implémenté sous la forme d’un SYN stealth scan complété par un mode UDP. Dans le cas TCP, le principe consiste à envoyer un segment SYN puis à interpréter la réponse du système distant. Un SYN-ACK indique généralement un port ouvert, un RST indique un port fermé et une absence de réponse suggère un filtrage ou une indisponibilité.

Lorsqu’un port TCP est déclaré ouvert, le moteur tente ensuite de récupérer une bannière afin d’identifier le service exposé. Cette information est utile pour le tableau de bord, car elle enrichit la matrice de ports et alimente les alertes de vulnérabilité potentielles. En UDP, la classification reste plus prudente, car l’absence de réponse ne permet pas toujours de trancher entre port ouvert et filtrage.

La figure 5 ci-dessous illustre l’affichage du scan de ports.

[FIGURE 5 — PortMatrix : ports groupés par hôte, avec code couleur pour les états open, closed et filtered, et bannière de service visible au survol.]

On peut observer que la représentation par cellules permet de lire rapidement l’état d’exposition d’un hôte. Cette approche visuelle est plus efficace qu’une simple liste textuelle lorsque plusieurs dizaines de ports sont examinés. Elle facilite aussi la mise en évidence des services sensibles comme le 445, le 3389 ou le 80.

## 2.3 Fingerprinting OS

L’identification du système d’exploitation s’appuie sur un fingerprinting multi-signal. Nous combinons trois indices : le TTL observé dans la réponse, la taille de la fenêtre TCP et le comportement face à une sonde de type Xmas. Cette combinaison est plus robuste qu’un seul signal isolé, car elle réduit les ambiguïtés entre familles de systèmes.

Le TTL fournit un premier indice sur l’architecture réseau sous-jacente. La fenêtre TCP complète cette première lecture en donnant une empreinte supplémentaire liée au système ou à sa pile réseau. Enfin, la sonde Xmas permet d’observer la réaction du système face à une combinaison de drapeaux inhabituelle, ce qui aide à distinguer les comportements Windows des comportements plus conformes à la RFC.

La figure 6 ci-dessous présente le panneau d’empreinte OS.

[FIGURE 6 — OSFingerprintPanel : hôte détecté, confidences par signal, TTL, fenêtre TCP et réponse Xmas consolidés dans une carte de synthèse.]

On peut observer que l’empreinte n’est pas présentée comme une vérité absolue, mais comme une hypothèse pondérée. Ce choix est pertinent sur le plan pédagogique, car il montre qu’une détection réseau repose souvent sur des indices probabilistes. Il évite également de surinterpréter un seul paquet comme une preuve définitive.

## 2.4 Règles de détection

Le projet met en œuvre plusieurs mécanismes de détection répartis entre le backend et l’agent victime. Dans le code actuellement livré, trois règles passives sont réellement implémentées dans le moteur de détection. Deux autres axes figurent comme prolongements naturels : la détection d’ICMP redirect et l’anomalie comportementale fondée sur l’apprentissage automatique. Nous les mentionnons ici de manière explicite afin de distinguer l’existant du futur souhaitable.

| ID | Description | Source | Statut | Sévérité |
|----|-------------|--------|--------|----------|
| DET-001 | ARP anomaly : changement de MAC pour une IP connue | Agent victime / backend | Implémenté | High |
| DET-002 | Port sweep : trop grand nombre de ports distincts dans une fenêtre donnée | Backend | Implémenté | Medium |
| DET-003 | SYN flood : volume anormal de SYN vers une cible | Agent victime / backend | Implémenté | Critical |
| DET-004 | ICMP redirect non sollicité | Attaques générées, détection à renforcer | Perspective | High |
| DET-005 | Détection d’anomalie par apprentissage automatique | Modèle comportemental | Perspective | Medium |

La détection ARP repose sur la comparaison d’un cache interne avec les réponses reçues. Dès qu’une adresse IP connue change de MAC, le système considère ce comportement comme suspect. Cette stratégie est adaptée à un laboratoire où le réseau reste stable, car toute variation devient immédiatement significative. Sur le plan pédagogique, elle rend visible le principe même de l’empoisonnement ARP.

Le port sweep est détecté en comptabilisant les ports distincts contactés par une même source dans une fenêtre glissante. Si le seuil est dépassé, une alerte est générée et le compteur est réinitialisé pour éviter une tempête d’événements. Cette approche est simple, efficace et facilement compréhensible, ce qui la rend parfaitement adaptée à un projet académique.

Le SYN flood est signalé lorsque la fréquence des paquets SYN devient anormale pour une même cible. L’agent victime et le backend collaborent alors pour produire une alerte et alimenter le tableau de bord. Ce mécanisme illustre bien la complémentarité entre une supervision locale proche du trafic et une diffusion centralisée vers le SOC.

## 2.5 Agent de détection

L’agent de détection est installé sur la machine Windows 10 et observe le trafic localement à l’aide de Scapy. Il capture principalement les paquets ARP et TCP, applique les règles de détection disponibles et transmet les alertes à l’API centrale. Cette position sur l’hôte victime est intéressante, car elle place la détection au plus près de l’impact réel de l’attaque.

L’agent envoie ses alertes sous forme de requêtes HTTP vers le backend, qui les persiste puis les redistribue en temps réel via WebSocket. Il envoie également des paquets de synthèse au routeur d’événements afin d’alimenter l’inspecteur de paquets dans l’interface. En parallèle, l’agent d’inventaire remonte périodiquement des informations d’état sur l’hôte, ce qui enrichit la supervision globale.

La figure 7 ci-dessous illustre le comportement de l’agent côté victime.

[FIGURE 7 — Terminal Windows 10 exécutant victim_agent.py : capture ARP/TCP active, alertes envoyées vers le backend et messages de statut visibles.]

On peut observer que l’agent remonte simultanément les signaux de sécurité et les métadonnées utiles à la supervision. Cette séparation entre alerte et inventaire améliore la lisibilité du SOC. Elle permet aussi de distinguer un événement de sécurité d’un simple état de la machine.

# Chapitre 3 — Backend et temps réel

Ce chapitre expose la colonne vertébrale applicative du projet. Nous y décrivons l’architecture ASGI, la pipeline de diffusion en temps réel, les endpoints REST, la gestion des threads et la stratégie de déploiement retenue avec Docker Compose.

## 3.1 Architecture ASGI

Le backend est construit avec Django 4.2.9 et Django Channels 4.0.0. Ce choix nous a permis de conserver une base web classique tout en ajoutant des WebSocket pour la supervision en temps réel. L’application ASGI constitue le point d’entrée unique qui route les requêtes HTTP vers Django et les connexions WebSocket vers les consommateurs Channels.

Cette architecture est intéressante parce qu’elle évite de multiplier les services spécialisés. Nous avons ainsi conservé un modèle mental simple : les requêtes structurées passent par l’API REST, tandis que les flux continus de paquets et d’alertes passent par les WebSocket. Cette séparation clarifie le rôle de chaque protocole et réduit les risques de confusion dans le code.

La figure 8 ci-dessous illustre cette organisation applicative.

[FIGURE 8 — Schéma ASGI : trafic HTTP vers l’API Django, trafic WebSocket vers les consommateurs Channels et distribution des événements vers le frontend React.]

On peut observer que l’architecture conserve un centre de gravité unique autour de Django. Ce point de conception simplifie le déploiement et la maintenance. Il permet également d’exposer facilement de nouveaux endpoints sans modifier la logique de transport.

## 3.2 WebSocket et pipeline temps réel

La couche temps réel repose sur des groupes WebSocket qui diffusent les événements aux clients connectés. Lorsqu’un thread de scan, de détection ou d’attaque produit un paquet ou une alerte, le backend convertit cet événement en message de groupe et l’envoie à l’ensemble des abonnés. Cette mécanique permet d’actualiser le SOC sans rafraîchissement manuel.

Le frontend écoute principalement le flux de session « live » et le flux dédié aux inventaires. L’inspecteur de paquets, le flux d’alertes et les vues de synthèse s’actualisent donc dès qu’un événement est reçu. Le choix d’une couche de canal en mémoire simplifie le déploiement et reste cohérent avec la taille du laboratoire.

La figure 9 ci-dessous montre le flux d’événements temps réel.

[FIGURE 9 — Pipeline temps réel : alertes, paquets, résultats de scan et inventaires routés vers les clients WebSocket du tableau de bord.]

On peut observer que l’interface n’est pas un simple consommateur passif de données, mais un véritable reflet du backend en activité. Cette continuité contribue fortement au caractère démonstratif du projet. Elle rend visibles les effets immédiats d’une attaque ou d’un scan.

## 3.3 API REST

L’API REST joue un rôle central dans la coordination entre les agents, les scans, les attaques et la consultation des résultats. Elle expose des routes dédiées à la découverte d’hôtes, au scan de ports, au fingerprinting OS, aux attaques ARP spoof et SYN flood, au stop des threads, à la réception des alertes et paquets, à l’ingestion d’inventaire, à l’enregistrement des agents, à la restitution des résultats et à l’export PDF.

Cette organisation par familles de fonctionnalités évite un backend monolithique opaque. Chaque endpoint a une responsabilité claire et retourne une réponse structurée immédiatement exploitable par le frontend. Le rapport de session et l’export PDF constituent un prolongement naturel de cette API, car ils donnent une forme exploitable aux données déjà collectées.

La figure 10 ci-dessous résume les principaux endpoints.

[FIGURE 10 — Carte des endpoints REST : découverte, scan, attaques, alertes, inventaire, registre d’agents, résultats de session et export PDF.]

On peut observer que l’API ne sert pas uniquement de canal technique, mais aussi de contrat entre les différents rôles du système. Ce contrat facilite l’automatisation côté frontend et côté agents. Il rend enfin le code plus lisible que des échanges ad hoc dispersés dans plusieurs scripts.

## 3.4 Gestion des threads

Les scans et attaques sont exécutés dans des threads Python afin de ne pas bloquer le serveur web. Un gestionnaire central associe chaque thread à un identifiant unique et à un événement d’arrêt. Ce mécanisme permet de lancer des opérations longues, de les surveiller et de les arrêter proprement depuis l’interface.

Le recours à des threads natifs est un choix pragmatique. Il évite l’introduction d’un courtier de tâches séparé tout en restant suffisant pour la charge observée dans un laboratoire de petite taille. Ce compromis rend la logique de contrôle plus directe et plus facile à enseigner.

Lorsqu’un arrêt est demandé, le thread reçoit un signal explicite, puis les modules réseau peuvent restaurer l’état initial, fermer leurs boucles et consigner la fin de l’opération. Cette approche est préférable à un arrêt brutal, qui risquerait de laisser le réseau dans un état incohérent.

## 3.5 Déploiement Docker

Le projet est orchestré par Docker Compose autour de trois services principaux : MongoDB, Django et React. MongoDB conserve les données du laboratoire, Django expose l’API et Channels, et React fournit l’interface utilisateur. Le proxy Nginx embarqué dans le frontend redirige les requêtes `/api/` et `/ws/` vers le backend accessible sur la machine hôte.

Ce déploiement présente un avantage majeur : il permet de relancer l’environnement de démonstration de manière reproductible, sans dépendre d’une installation manuelle complexe. Les privilèges nécessaires à Scapy sont donnés au conteneur backend via `NET_RAW` et `NET_ADMIN`, ce qui autorise les opérations réseau requises dans un cadre de laboratoire. Le backend utilise Daphne comme serveur ASGI, ce qui complète naturellement l’usage de Channels.

La figure 11 ci-dessous représente l’organisation du déploiement conteneurisé.

[FIGURE 11 — Schéma Docker Compose : service MongoDB, service Django/Daphne et service React/Nginx, reliés dans un environnement reproductible.]

On peut observer que la séparation des services rend les responsabilités plus lisibles et les incidents plus faciles à diagnostiquer. Le backend reste focalisé sur la logique métier, tandis que le frontend se concentre sur la présentation. Cette segmentation est particulièrement utile pour un projet académique qui doit être à la fois démonstratif et maintenable.

# Chapitre 4 — Interface SOC (Frontend)

Ce chapitre est consacré à la couche de supervision visible par l’analyste. Nous y présentons le design system, le dashboard temps réel, la visualisation réseau, l’inspecteur de paquets, la console d’attaque, le rapport de session et la gestion des agents.

## 4.1 Design system

L’interface frontend repose sur une esthétique sombre, contrastée et orientée supervision. Nous avons choisi une hiérarchie visuelle claire : fond app sombre, cartes de contenu légèrement relevées, accent coloré cyan et sévérités codées par des couleurs facilement identifiables. Cette direction graphique soutient la lisibilité des alertes et évite l’effet d’un tableau de bord générique.

Le système de navigation sépare les usages en plusieurs zones : SOC, cartographie réseau, outils de scan, console d’attaque, rapport de session, endpoints et inventaire. Ce choix reflète les besoins réels d’un opérateur qui doit alterner entre observation, investigation et action. Il permet aussi de garder une logique cohérente dans une application riche en composants.

La figure 12 ci-dessous montre l’écran de connexion du SOC.

[FIGURE 12 — LoginPage : carte de connexion sécurisée sur fond animé, champ email, mot de passe et identité visuelle du projet ReconTool.]

On peut observer que l’écran de connexion n’est pas seulement fonctionnel ; il donne aussi une première impression de contexte opérationnel. Cette mise en scène renforce l’idée d’un environnement de supervision dédié au laboratoire. Elle prépare visuellement l’utilisateur à la lecture des données de sécurité.

## 4.2 Dashboard temps réel

Le tableau de bord SOC est la vue la plus dynamique de l’application. Il agrège les alertes, les indicateurs de trafic, l’état des agents et les signaux d’activité récemment observés. Les cartes KPI affichent les informations les plus utiles pour un diagnostic rapide, tandis que le flux d’alertes met en évidence les événements de sécurité les plus récents.

Le tableau de bord s’appuie sur les données diffusées par WebSocket, ce qui lui permet de rester à jour sans rechargement. Les alertes sont normalisées avant affichage afin d’éviter les crashs liés à des messages incomplets ou non conformes. Cette robustesse est importante, car un SOC ne doit pas devenir instable au premier événement mal formé.

La figure 13 ci-dessous illustre la vue principale du SOC.

[FIGURE 13 — SOCDashboard : cartes KPI, flux d’alertes, indicateurs agents et métriques réseau mis à jour en temps réel.]

On peut observer que la présentation privilégie la lecture immédiate des informations critiques. Les badges de sévérité, les codes couleur et les timestamps monospace facilitent la reconnaissance rapide d’un incident. Cette lisibilité est indispensable pour une supervision efficace.

## 4.3 Visualisation réseau

La visualisation réseau est assurée par un graphe force-directed construit avec D3.js. Chaque nœud représente un hôte découvert, coloré selon son système d’exploitation estimé. La vue est interactive : l’utilisateur peut zoomer, déplacer les nœuds et inspecter les informations de base via une infobulle.

Cette représentation a été choisie parce qu’elle permet de saisir rapidement la topologie logique du laboratoire. Contrairement à un simple tableau d’hôtes, un graphe révèle les relations, les proximités et l’évolution de la carte au fil des découvertes. Il constitue donc un excellent support de démonstration.

La figure 14 ci-dessous présente la cartographie réseau.

[FIGURE 14 — NetworkMap D3.js : graphe interactif des hôtes, avec coloration par OS, zoom, drag-and-drop et infobulles détaillées.]

On peut observer que l’interface donne une lecture immédiate de la topologie sans sacrifier la densité d’information. Cette visualisation complète utilement le tableau des résultats de scan. Elle transforme des métadonnées réseau en représentation compréhensible au premier regard.

## 4.4 Analyse paquets

L’inspecteur de paquets affiche le flux brut des événements réseau capturés pendant les scans, les attaques et la supervision. Les colonnes essentielles sont conservées : timestamp, protocole, flags, TTL, chemin source-destination et résumé. Cette structure facilite à la fois l’analyse rapide et le filtrage détaillé.

Le composant permet de mettre en pause le flux, de filtrer les paquets et de limiter le nombre de lignes affichées pour garder de bonnes performances. Nous avons privilégié un style proche du terminal, car cette esthétique correspond bien à un outil de sécurité. Elle met aussi en évidence la dimension technique du trafic observé.

La figure 15 ci-dessous illustre l’inspecteur de paquets.

[FIGURE 15 — PacketInspector : flux de paquets en direct, couleurs par protocole et flags, compteur pkt/s et fonction de filtrage.]

On peut observer que la lecture du flux devient très expressive lors d’un SYN flood ou d’une attaque ARP spoof. Les couleurs et les badges permettent d’identifier immédiatement la nature du trafic. Cette représentation enrichit considérablement l’analyse opérationnelle.

## 4.5 Console d’attaque

La console d’attaque permet de lancer les scénarios autorisés dans le laboratoire : ARP spoof, SYN flood et ICMP redirect. Chaque carte d’attaque expose ses paramètres et son état d’exécution, avec un bouton de lancement et un bouton d’arrêt. L’interface rappelle explicitement le caractère strictement expérimental de ces opérations.

Le design de cette console vise la clarté et la prévention des erreurs. Les attaques en cours sont signalées par un badge visible et des accents colorés plus agressifs. Cette signalétique est utile, car elle réduit le risque de confondre un test actif et un état d’attente.

La figure 16 ci-dessous montre la console d’attaque.

[FIGURE 16 — AttackConsole : cartes ARP Spoof, SYN Flood et ICMP Redirect, avec statuts Idle/Running et journal d’activité.]

On peut observer que l’utilisateur dispose d’un contrôle direct sur les scénarios de laboratoire. L’interface fait le lien entre génération d’attaque et supervision. Elle illustre concrètement la chaîne complète du projet.

## 4.6 Rapport de session

Le rapport de session synthétise les hôtes, les ports, les alertes et les indicateurs consolidés d’une campagne donnée. Cette vue est importante, car elle transforme un flux d’événements en document exploitable pour la restitution académique. Elle sert aussi de base à l’export PDF généré côté backend.

Le graphique de ports et la liste des hôtes facilitent la lecture d’ensemble. Les alertes y sont regroupées par sévérité et présentées de manière structurée. Cette consolidation améliore la relecture d’une session sans avoir à revenir à l’intégralité du flux temps réel.

La figure 17 ci-dessous présente le rapport de session.

[FIGURE 17 — SessionReport : synthèse d’une session, graphique de répartition des ports et liste des alertes avec export PDF.]

On peut observer que cette page joue un rôle de transition entre l’observation en direct et l’archivage. Elle clôt proprement une campagne de test. Elle produit une trace lisible, réutilisable dans un cadre de validation ou de restitution.

## 4.7 Gestion des agents

La gestion des agents est assurée par deux vues complémentaires : `Endpoints` et `Inventory`. La première consolide la présence des agents enregistrés et des machines effectivement vues par le système, tandis que la seconde détaille l’inventaire remonté par les VM. Cette distinction nous permet de séparer l’enregistrement administratif du retour opérationnel.

La page Endpoints donne une vision synthétique : agents actifs, état de présence et concordance entre le registre et l’inventaire. La page Inventory, quant à elle, expose davantage de détails sur le système hôte, les interfaces, la mémoire, les services et les ports ouverts. Ensemble, ces deux pages enrichissent la supervision avec une dimension plus proche de l’administration système.

La figure 18 ci-dessous montre les vues de gestion des agents.

[FIGURE 18 — Endpoints et Inventory : liste des agents, synchronisation registre/inventaire, état de présence et détails système.]

On peut observer que l’analyste dispose à la fois d’une vue de haut niveau et d’une vue détaillée. Cette articulation est utile pour relier un événement de sécurité à la configuration réelle d’un poste. Elle rend l’interface plus utile qu’un simple tableau de logs.

# Chapitre 5 — Tests et résultats

Ce chapitre rassemble les conditions de validation du projet, les scénarios exécutés, les résultats observables et les limites identifiées. L’objectif n’est pas seulement de confirmer le bon fonctionnement, mais aussi d’évaluer la cohérence d’ensemble du système dans son environnement de laboratoire.

## 5.1 Environnement de test

Les validations ont été menées dans un laboratoire VirtualBox isolé sur le sous-réseau 192.168.56.0/24. L’hôte exécute la pile conteneurisée, la VM Kali Linux génère les attaques et la VM Windows 10 héberge l’agent de détection ainsi que l’agent d’inventaire. Cette topologie correspond au scénario prévu par l’architecture du projet.

Le tableau suivant résume l’environnement principal utilisé pour les essais.

| Paramètre | Valeur |
|-----------|--------|
| Machine hôte | Station de développement sous Linux ou Windows avec Docker |
| Réseau VirtualBox | Host-Only 192.168.56.0/24 |
| VM attaquante | Kali Linux |
| VM victime | Windows 10 |
| Backend | Django 4.2.9 + Channels 4.0.0 |
| Base de données | MongoDB 6 |
| Capture réseau | Scapy 2.5.0 |
| Génération de PDF | ReportLab 4.1.0 |
| Frontend | React 18 + D3.js + Recharts |

Ce cadre de test est volontairement sobre. Il reproduit un environnement de laboratoire réaliste sans imposer d’infrastructure externe. Il permet de vérifier le comportement de l’application de bout en bout, depuis l’attaque jusqu’à l’affichage des alertes.

## 5.2 Scénarios et résultats

Les scénarios exécutés couvrent les principales fonctionnalités livrées par le projet. Nous avons inclus les attaques, la découverte réseau, le scan de ports, le fingerprinting OS, l’ingestion d’inventaire et l’export PDF. Le tableau suivant synthétise ces validations.

| Scénario | Résultat attendu | Résultat observé | Statut |
|----------|------------------|------------------|--------|
| SYN flood vers la VM victime | Alerte de type SYN flood et affichage temps réel | Alerte visible dans le SOC et dans le flux paquets | Validé |
| ARP spoofing | Alerte ARP anomaly et mise à jour du flux | Détection et affichage immédiats | Validé |
| ICMP redirect | Génération de l’attaque et présence dans les paquets | Attaque émise et visible dans l’inspecteur | Validé |
| ARP sweep du sous-réseau | Découverte des hôtes actifs | Hôtes ajoutés à la carte réseau | Validé |
| SYN stealth scan | Classification open/closed/filtered | Résultats visibles dans la matrice de ports | Validé |
| UDP scan | Classification prudente des ports UDP | Résultats exploités par la matrice | Validé |
| Fingerprinting OS | Attribution d’un OS probable | Panneau OS renseigné avec confiance | Validé |
| Ingestion d’inventaire | Mise à jour de la liste des agents | Données affichées dans Inventory et Endpoints | Validé |
| Export PDF | Génération d’un rapport de session | PDF téléchargeable depuis l’interface | Validé |

Ces résultats montrent que la chaîne fonctionnelle est cohérente et complète pour le périmètre défini. Chaque fonctionnalité importante du projet dispose d’un chemin d’exécution visible et d’une restitution dans l’interface. Cela confirme l’intérêt d’une architecture unifiée où le backend, le frontend et les agents coopèrent autour d’un même contexte de session.

## 5.3 Analyse des performances

L’évaluation des performances a surtout porté sur la fluidité de la supervision et sur la capacité à conserver une lecture claire en situation de trafic soutenu. L’usage d’un canal en mémoire, de threads Python et d’une interface React rend le système léger et réactif dans le cadre du laboratoire. L’inspecteur de paquets reste lisible même lorsque les événements s’enchaînent rapidement.

Le backend n’introduit pas de dépendance à un broker externe, ce qui réduit la complexité de déploiement et de diagnostic. La diffusion des alertes via WebSocket permet à l’analyste de voir les événements apparaître sans rechargement de page. Cette réactivité est précisément ce que nous recherchions : une supervision vivante, mais suffisamment simple pour rester compréhensible dans un contexte académique.

Sur le plan pratique, la conception modulaire facilite aussi l’évolution du système. Les scans, la détection, les vues WebSocket et la restitution frontend sont séparés par responsabilités, ce qui autorise des ajustements localisés. Cette propriété est importante pour un projet de fin d’année, car elle montre que l’architecture a été pensée pour être comprise et maintenue.

## 5.4 Limites et perspectives

La principale limite actuelle est l’absence d’une couche d’anomalie comportementale avancée intégrée au moteur de détection. Le projet couvre déjà des règles très utiles pour un laboratoire, mais il gagnerait à intégrer un module d’apprentissage automatique entraîné sur un jeu de données étiqueté. Une telle évolution permettrait de compléter les signatures existantes par une logique plus souple.

Une seconde perspective concerne la sécurité de transport. Les échanges entre les agents et le backend pourraient être protégés par TLS afin d’éviter toute interception triviale. De même, une authentification plus stricte des agents renforcerait la robustesse de la chaîne d’ingestion.

Une troisième évolution naturelle serait de remplacer la couche de canal en mémoire par un backend plus résilient lorsque le projet doit dépasser le cadre du laboratoire. Enfin, l’enrichissement de la cartographie par des corrélations plus fines, voire par des données de vulnérabilités externes, offrirait une profondeur d’analyse supplémentaire.

# Conclusion générale

Ce projet nous a permis de réaliser un système de détection d’intrusions réseau complet, cohérent et pleinement exploitable dans un laboratoire de démonstration. De la découverte d’hôtes à la supervision SOC, en passant par le scan de ports, le fingerprinting OS, les attaques simulées et la remontée d’alertes, nous avons construit une chaîne fonctionnelle homogène. Le résultat est un environnement qui montre concrètement comment un événement réseau devient une information de sécurité.

Sur le plan technique, nous avons consolidé notre compréhension de Scapy, de Django, de Django Channels, de MongoEngine et de React. Le projet nous a également confrontés à des problématiques d’architecture, de découplage des responsabilités et de diffusion temps réel. Cette combinaison de compétences réseau, backend et frontend constitue l’un des apports majeurs du travail.

La dimension pédagogique du projet est particulièrement importante. En maîtrisant nous-mêmes les différents composants, nous avons pu suivre les paquets depuis leur émission jusqu’à leur affichage dans le SOC, sans recourir à une solution fermée ou opaque. Cette transparence nous semble essentielle dans un projet de fin d’année, car elle démontre une compréhension réelle des mécanismes de sécurité.

Plusieurs améliorations peuvent prolonger ce travail : ajout d’une détection comportementale avancée, renforcement de la sécurité des échanges par TLS et authentification, migration vers une couche de canal plus robuste et enrichissement de la cartographie par des corrélations supplémentaires. Ces perspectives ne remettent pas en cause la valeur du système actuel ; elles en dessinent simplement la suite logique dans un contexte académique ou de recherche appliquée.

# Bibliographie

[1] K. Scarfone and P. Mell, “Guide to Intrusion Detection and Prevention Systems (IDPS),” NIST SP 800-94, Feb. 2007.

[2] V. Chandola, A. Banerjee, and V. Kumar, “Anomaly Detection: A Survey,” ACM Computing Surveys, vol. 41, no. 3, pp. 1–58, 2009.

[3] W. R. Stevens, *TCP/IP Illustrated, Volume 1: The Protocols*, 2nd ed. Addison-Wesley, 2011.

[4] R. Bejtlich, *The Practice of Network Security Monitoring*. No Starch Press, 2013.

[5] P. Biondi, “Scapy: explore the net with new eyes,” EUSecWest, 2011. Available: https://scapy.net/.

[6] Django Software Foundation, “Django Documentation: ASGI, Channels and Daphne,” Django 4.2 Docs, 2024. Available: https://docs.djangoproject.com/.

[7] M. Bostock, “D3.js — Data-Driven Documents,” IEEE Trans. Vis. Comput. Graph., vol. 17, no. 12, pp. 2301–2309, Dec. 2011.

[8] F. Pedregosa et al., “Scikit-learn: Machine Learning in Python,” JMLR, vol. 12, pp. 2825–2830, 2011.

[9] Docker Inc., “Docker Documentation: Compose, Networking and Security,” 2024. Available: https://docs.docker.com/.

[10] MongoDB Inc., “MongoDB Manual: Aggregation, Indexing and Storage,” 2024. Available: https://www.mongodb.com/docs/.

[11] D. C. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, Nov. 1982.

[12] J. Postel, “Transmission Control Protocol,” RFC 793, Sept. 1981.
