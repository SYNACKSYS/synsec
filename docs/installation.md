# Installation

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

| Plateforme | Protection | Disque volé |
|---|---|---|
| Windows | DPAPI, lié à la machine | inexploitable |
| Linux avec TPM | scellée dans la puce TPM | inexploitable |
| Linux sans TPM | fichier réservé au service | **exploitable** |

Dans le dernier cas, SYNSEC te le dit franchement : la clé dort à côté de la
base. Chiffre le disque si la machine est exposée.

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
