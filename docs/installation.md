# Installation

## Télécharger

Les binaires publiés se trouvent dans les
[releases](https://github.com/SYNACKSYS/synsec/releases). Un seul fichier à
poser, rien à installer à côté.

| Fichier | Pour |
|---|---|
| `synsec-windows-amd64.exe` | Windows |
| `synsec-linux-amd64` | Linux et Synology sur processeur Intel |
| `synsec-linux-arm64` | Raspberry Pi 3/4/5 en 64 bits, Synology ARM |
| `synsec-linux-armv7` | Raspberry Pi en 32 bits |
| `synsec-macos-apple` / `-intel` | macOS |

En cas de doute sur l'architecture, sur la machine cible : `uname -m`. `x86_64`
donne `amd64`, `aarch64` donne `arm64`, `armv7l` donne `armv7`.

Chaque release contient un fichier `SHA256SUMS`. Vérifier ce que tu as
téléchargé prend dix secondes et vaut la peine pour un logiciel qui va détenir
tous tes mots de passe :

```
certutil -hashfile synsec-windows-amd64.exe SHA256
sha256sum -c SHA256SUMS
```

Sous Linux et macOS, il faut aussi rendre le fichier exécutable :

```
chmod +x synsec-linux-amd64
```


Compte une dizaine de minutes. À la fin, SYNSEC démarrera tout seul avec la
machine et sera joignable depuis ton réseau.

## Ce qu'il te faut

- Une machine qui reste allumée : un vieux PC, un NUC, un Raspberry Pi, une
  machine virtuelle. Windows ou Linux.
- Le fichier `synsec` (ou `synsec.exe`). Un seul fichier, rien à installer.
- Quelques minutes en administrateur, une seule fois.

SYNSEC consomme environ 25 Mo de mémoire au repos et ne sollicite le processeur
qu'au moment où un appareil lui demande quelque chose.

## 1. Poser le binaire

Choisis un emplacement stable - le service pointera dessus.

**Windows**

```
mkdir C:\SYNSEC
copy synsec.exe C:\SYNSEC\
cd C:\SYNSEC
```

**Linux**

```
sudo cp synsec /usr/local/bin/
sudo chmod +x /usr/local/bin/synsec
```

## 2. Préparer le serveur

```
synsec init
```

Cette commande crée la clé de chiffrement, la scelle à cette machine, et
affiche un **code de récupération**.

> **Imprime ce code et range-le ailleurs que sur ce serveur.**
>
> Il ne sera plus jamais affiché. C'est la seule façon de rouvrir tes secrets
> si la machine tombe en panne, si tu réinstalles le système, ou si le compte
> de service change. Sans lui, une carte mère grillée signifie tout perdre.
>
> Une feuille de papier dans un tiroir fait très bien l'affaire.

La commande indique aussi comment la clé est protégée sur ta machine :

| Plateforme | Protection | Sauvegarde emportée | Disque entier volé |
|---|---|---|---|
| Windows | DPAPI, lié à la machine | inexploitable | **exploitable sans BitLocker** |
| Linux avec TPM | scellée dans la puce TPM | inexploitable | inexploitable |
| Linux sans TPM | fichier réservé au service | **exploitable** | **exploitable** |

Les deux colonnes ne disent pas la même chose, et la différence compte.

Une **sauvegarde du dossier de données** restaurée ailleurs est inexploitable
sur Windows comme sur un Linux à TPM : ce qui ouvre la clé n'y figure pas.

Un **disque entier** est un autre sujet. Sous Windows, ce qui déchiffre la clé
DPAPI vit ailleurs sur ce même disque : qui repart avec le disque repart avec
les deux moitiés. C'est **BitLocker** qui ferme cet écart, pas SYNSEC. Sur un
Linux à TPM, la clé ne quitte jamais la puce, et le disque seul ne suffit pas.

Sans TPM ni BitLocker, SYNSEC le dit franchement à l'installation : la clé dort
à côté de la base.

### Où vont les données

| Plateforme | Dossier |
|---|---|
| Windows | `C:\ProgramData\SYNSEC` |
| Linux | `/var/lib/synsec` |

Tu peux en choisir un autre avec `-data` sur chaque commande, ou une fois pour
toutes avec la variable d'environnement `SYNSEC_DATA_DIR`.

Pour un essai, un dossier local évite d'avoir à être administrateur :

```
synsec init -data .\data
```

## 3. Faire accepter le certificat

SYNSEC ne répond **qu'en HTTPS**. Il n'existe aucun mode HTTP : une adresse
tapée en `http://` est renvoyée vers `https://`, et rien d'autre ne transite en
clair.

Comme il n'y a ni nom de domaine public ni autorité de certification, SYNSEC
génère son propre certificat. Il faut le faire accepter par la machine, une
fois, **en administrateur** :

**Windows** - invite de commande lancée en tant qu'administrateur :

```
synsec cert trust
```

**Linux** :

```
sudo synsec cert trust
```

Sans cette étape, ton navigateur affichera un avertissement et certains clients
refuseront purement et simplement de se connecter.

### Les autres machines du réseau

Le certificat se trouve dans le dossier de données, sous `synsec.crt`. Pour
qu'un autre poste l'accepte, copie ce fichier et installe-le dans ses autorités
de confiance. `synsec cert show` rappelle son emplacement et son empreinte.

**Firefox fait exception** : il gère son propre magasin et ignore celui du
système. Il faut l'y importer à la main, dans *Paramètres / Vie privée et
sécurité / Certificats / Afficher les certificats / Autorités / Importer*, en
cochant « Confirmer cette AC pour identifier des sites web ».

## 4. Créer ton compte

```
synsec utilisateur create cyril
```

Le mot de passe est demandé deux fois, sans être affiché. Dix caractères au
minimum.

Le **premier** compte devient automatiquement administrateur. C'est le seul que
la ligne de commande crée librement : tous les suivants exigeront le code de
récupération, ou passeront par l'interface web.

## 5. Installer le service

En administrateur (Windows) ou avec `sudo` (Linux) :

```
synsec service install
```

SYNSEC démarrera désormais avec la machine, avant même qu'un utilisateur ouvre
une session, et se relancera de lui-même après une panne - trois tentatives, à
5 s, 15 s et 60 s.

Pour vérifier :

```
synsec service status
```

### Options

```
synsec service install -listen :9000
synsec service install -data D:\SYNSEC
```

Le dossier de données est enregistré en chemin absolu dans la définition du
service : un service démarre avec un répertoire courant que personne n'a
choisi, un chemin relatif pointerait n'importe où.

## 6. Vérifier

Ouvre `https://<nom-de-ta-machine>:8787/` dans un navigateur. Tu dois arriver
sur l'écran de connexion.

Depuis n'importe quelle machine du réseau, sans authentification :

```
curl https://<nom-de-ta-machine>:8787/api/v1/health
```

La réponse attendue est `{"status":"ready"}`. Si elle dit `sealed`, le serveur
tourne mais n'a pas réussi à ouvrir son coffre - voir
[Administration](administration.md#le-serveur-ne-souvre-plus).

**Le test qui compte vraiment** : redémarre la machine, ne te connecte pas, et
refais l'appel depuis un autre poste. C'est le scénario réel, celui de la
coupure de courant à trois heures du matin.

## 7. Chiffrer le disque

Cette étape ne fait pas partie de SYNSEC, et c'est exactement pour ça qu'elle
mérite d'être écrite : sans elle, la protection de la clé s'arrête à mi-chemin
sur Windows.

### Windows

Vérifier l'état actuel, dans une invite de commandes en administrateur :

```
manage-bde -status C:
```

Si la protection est désactivée, l'activer :

```
manage-bde -on C: -RecoveryPassword
```

La commande affiche une **clé de récupération BitLocker de 48 chiffres**.
Range-la comme le code de récupération de SYNSEC : ailleurs que sur cette
machine, et pas au même endroit que la sauvegarde. Ce sont deux secrets
différents qui répondent à deux pannes différentes.

Sans TPM, Windows refuse par défaut et demande une clé de démarrage sur clé
USB. Sur une machine domestique laissée allumée, c'est souvent le moment de se
demander si le TPM ne peut pas être activé dans le firmware.

### Linux

Le chiffrement du volume se met en place à l'installation du système, avec
LUKS. Sur une machine déjà en service, c'est une réinstallation.

Avec un TPM, l'urgence est moindre : la clé racine de SYNSEC est scellée dans
la puce et ne se trouve pas sur le disque. Sans TPM, la clé dort dans
`root.key` à côté de la base, et LUKS est la seule chose qui rattrape ça.

### Ce que ça change, et ce que ça ne change pas

Le chiffrement du volume protège la machine **éteinte** : disque retiré, poste
volé, serveur mis au rebut sans effacement.

Il ne protège pas une machine allumée. Un administrateur du système en marche
obtient la clé de la même façon que le service, et c'est le compromis assumé
qui permet à SYNSEC de redémarrer seul après une coupure. Voir
[le modèle de menace](../README.md#ce-que-la-sécurité-couvre-et-ce-quelle-ne-couvre-pas).

## Sans service, au premier plan

Pour un essai ou un diagnostic :

```
synsec serve -data .\data
```

`Ctrl+C` arrête proprement : les requêtes en cours reçoivent leur réponse
plutôt qu'une connexion coupée.

## Résolution des ennuis

**Le navigateur affiche « Non sécurisé ».** Le certificat n'est pas accepté.
Relance `synsec cert trust` en administrateur, ferme et rouvre le navigateur.
Sous Firefox, voir plus haut : il faut l'importer séparément.

**Le service s'installe mais ne démarre pas.** Le journal explique pourquoi :

```
type C:\ProgramData\SYNSEC\synsec.log
```

La cause la plus fréquente est un descellement impossible, parce que la machine
a été réinstallée ou le dossier de données déplacé. Voir
[la récupération](administration.md#rouvrir-le-coffre-avec-le-code).

**PowerShell 5.1 refuse de se connecter.** La version livrée avec Windows
négocie encore en TLS 1.0 par défaut, que les serveurs récents refusent. Dans
une fenêtre neuve :

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

`curl.exe`, livré avec Windows, n'a pas ce défaut et reste le plus simple pour
tester.

**Le port 8787 est déjà pris.** Choisis-en un autre :

```
synsec service install -listen :9000
```
