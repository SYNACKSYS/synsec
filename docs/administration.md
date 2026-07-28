# Administration

Comptes, sauvegarde, récupération, et ce qu'il faut savoir quand ça tourne mal.

## Le modèle de droits

Trois choses distinctes, souvent confondues ailleurs.

**Administrateur du serveur.** Gère les comptes : en créer, en supprimer,
réinitialiser un mot de passe. Rien de plus. Il **ne voit aucun coffre** qu'il
n'a pas créé ou qu'on ne lui a pas partagé, exactement comme n'importe qui.

**Compte principal.** Le tout premier créé, celui avec lequel le serveur a été
installé. C'est un administrateur, plus une chose que les autres n'ont pas : il
lit le journal d'audit et décide qui d'autre le lit.

**Propriétaire d'un coffre.** Celui qui l'a créé. Le coffre apparaît dans ses
« Mes coffres », et chez les autres dans « Coffres partagés avec moi ».

**Rôle sur un coffre** - lecture, écriture, gestion. Indépendant de la
propriété : on peut être gestionnaire d'un coffre qui appartient à quelqu'un
d'autre.

> **Ce que cette séparation vaut, exactement.**
>
> C'est une règle appliquée par SYNSEC, pas une barrière cryptographique. Un
> administrateur peut réinitialiser un mot de passe et se connecter sous
> l'identité de quelqu'un, ou lire la base directement puisque la clé racine
> est déscellée automatiquement au démarrage.
>
> Ce que ça achète : la curiosité ordinaire devient un acte délibéré, et tout
> accès laisse une trace nominative. Ce n'est pas rien, mais ce n'est pas une
> garantie.

## Les comptes

### Depuis l'interface

**Comptes** dans le menu, visible des seuls administrateurs. Chaque ligne porte
ses actions : **Mot de passe** et **Supprimer**. Le formulaire de création est
sous la liste.

Créer un compte n'ouvre aucun coffre. La personne arrive sur une page vide et
ne verra que ce qu'on lui partagera ensuite.

Changer un mot de passe ferme toutes les sessions ouvertes de la personne
concernée - sans quoi un mot de passe changé parce qu'il avait fuité laisserait
la fuite en place.

### Depuis la ligne de commande

```
synsec utilisateur list
synsec utilisateur create alice
synsec utilisateur create alice -admin
synsec utilisateur passwd alice
synsec utilisateur rm alice
```

**Sauf pour le tout premier compte, ces commandes exigent le code de
récupération.** C'est délibéré : créer un compte est la seule opération qui
accorde un accès sans qu'aucun accès préexiste. Sans cette garde, quiconque
atteint le dossier de données s'ouvrirait l'interface en une commande.

L'interface web reste le chemin normal ; la ligne de commande est un bris de
glace.

### Ce que SYNSEC refuse

- Supprimer son propre compte.
- Supprimer le compte principal - lui seul peut ouvrir le journal d'audit à
  quelqu'un, et rien ne peut prendre sa place ensuite.
- Supprimer le dernier administrateur - plus personne ne pourrait gérer les
  comptes.
- Supprimer le seul gestionnaire d'un coffre - le coffre deviendrait
  inaccessible à tout le monde, y compris aux administrateurs. Le message nomme
  les coffres concernés.
- Retirer le dernier gestionnaire d'un coffre, pour la même raison.

## Sauvegarder

Tout tient dans le dossier de données :

| Fichier | Contenu |
|---|---|
| `synsec.db` | la base : coffres, secrets chiffrés, comptes, journal |
| `synsec.crt` / `synsec.key` | le certificat TLS |
| `root.key` | la clé racine, **sur les machines sans TPM uniquement** |

Arrête le service, copie le dossier, redémarre :

```
net stop SYNSEC
xcopy /E /I C:\ProgramData\SYNSEC D:\sauvegardes\synsec-2026-07-26
net start SYNSEC
```

Sous Linux :

```
sudo systemctl stop synsec
sudo tar czf /sauvegardes/synsec-2026-07-26.tar.gz /var/lib/synsec
sudo systemctl start synsec
```

La base peut être copiée à chaud - SQLite est en mode WAL - mais un arrêt évite
d'avoir à y réfléchir.

> **Une sauvegarde ne suffit pas.** Sur Windows et sur Linux avec TPM, la clé
> racine est scellée à la machine et ne figure **pas** dans la sauvegarde.
> Restaurée ailleurs, la base est illisible sans le code de récupération.
>
> C'est voulu : c'est ce qui rend une sauvegarde volée inexploitable. Mais ça
> veut dire que **la sauvegarde et le code de récupération se conservent
> séparément, et qu'il faut les deux**.

## Restaurer

Sur une machine neuve :

1. Pose le binaire et restaure le dossier de données.
2. Ne lance pas `init` - le coffre existe déjà.
3. Rouvre-le avec le code de récupération :

```
synsec recover
```

Cette commande ouvre le coffre avec le code imprimé, puis **rescelle** la clé à
la machine courante. Sans ce rescellement, il faudrait ressaisir le code à
chaque démarrage.

4. Refais accepter le certificat, puis réinstalle le service :

```
synsec cert trust
synsec service install
```

Le code de récupération reste valable après une restauration. Garde-le.

## Utiliser son propre certificat

Par défaut SYNSEC émet le sien, et `synsec cert trust` l'installe dans le
magasin de la machine. Pour un serveur qui porte un vrai nom de domaine, tu
peux fournir le tien :

```
synsec serve -tls-cert /etc/letsencrypt/live/exemple.fr/fullchain.pem \
             -tls-key  /etc/letsencrypt/live/exemple.fr/privkey.pem
```

Ou par l'environnement, ce qui convient mieux à une unité systemd :

```
SYNSEC_TLS_CERT=/etc/letsencrypt/live/exemple.fr/fullchain.pem
SYNSEC_TLS_KEY=/etc/letsencrypt/live/exemple.fr/privkey.pem
```

Les deux vont ensemble : SYNSEC refuse de démarrer avec l'un sans l'autre.

### La chaîne complète, pas seulement la feuille

Le fichier de certificat doit contenir la feuille **puis les intermédiaires** -
c'est `fullchain.pem` chez Let's Encrypt, pas `cert.pem`. Avec la feuille
seule, la connexion réussit depuis les machines qui ont déjà l'intermédiaire en
cache et échoue depuis les autres. La panne semble alors aléatoire, ce qui est
la pire sorte.

### Le renouvellement est pris en compte tout seul

SYNSEC surveille les deux fichiers et recharge le certificat quand ils
changent, sans redémarrage. Ton client ACME renouvelle, la connexion suivante
présente le nouveau certificat.

Deux garde-fous : un fichier à moitié écrit ou temporairement absent - ce qui
arrive pendant un renouvellement - n'interrompt rien, l'ancien certificat reste
en service et le journal l'explique. Et un chemin erroné est refusé au
démarrage plutôt qu'à la première connexion, une heure plus tard.

### Une autorité publique et une adresse privée

Aucune autorité publique ne signera pour `192.168.1.10`. Si ton serveur ne sort
pas sur Internet, il te faut un vrai nom de domaine et un défi **DNS-01**, le
seul qui n'exige pas que le serveur soit joignable depuis l'extérieur.

Sur un réseau strictement domestique, le certificat auto-signé et
`synsec cert trust` restent plus simples et pas moins sûrs : tu deviens ta
propre autorité, pour toi seul.

## Le délai d'inactivité

L'interface web déconnecte un navigateur laissé sans activité pendant **30
minutes**. Chaque page consultée remet le compteur à zéro, donc une session en
cours d'utilisation ne se ferme jamais d'elle-même : ce qui expire, c'est
l'onglet oublié sur une machine déverrouillée.

Deux façons de changer la valeur :

```
synsec serve -session-idle 8h
SYNSEC_SESSION_IDLE=8h
```

Elle est bornée entre une minute et trente jours, et une valeur illisible
retombe sur le défaut plutôt que d'empêcher le serveur de démarrer.

Un plafond absolu de trente jours s'applique en plus : aussi active soit-elle,
une session finit par redemander le mot de passe. Il n'est pas configurable.

La tablette de la cuisine est le cas qui souffre le plus de ce réglage. Si
elle affiche l'interface en permanence, monte le délai plutôt que de
contourner : `-session-idle 12h` reste très au-dessus de ce qu'un onglet
oublié tient sans que personne y touche.

## Exposer le serveur sur Internet

SYNSEC est pensé pour un réseau domestique. Rien n'empêche de l'exposer, mais
les hypothèses changent, et quatre réglages deviennent nécessaires.

**La façon la plus sûre reste de ne pas l'exposer.** Un tunnel WireGuard ou
Tailscale devant supprime d'un coup tout ce qui suit, pour une demi-heure de
configuration.

### Restreindre l'interface à des adresses

L'API a des listes blanches par jeton ; le navigateur n'avait rien.

```
synsec serve -web-allow 192.168.1.0/24,203.0.113.7
```

Une adresse hors liste est refusée avant le routage et avant toute recherche de
session : elle n'atteint même pas le formulaire de connexion, et ne coûte donc
aucun calcul de mot de passe.

### Nommer les proxies

Derrière un proxy inverse, `X-Forwarded-For` doit être cru - mais seulement
venant de lui :

```
synsec serve -trusted-proxies 10.0.0.0/8
```

Sans cette option, l'en-tête est ignoré, ce qui est le bon défaut : le croire
sans condition laisserait n'importe quel appelant choisir l'adresse contre
laquelle ses restrictions sont vérifiées. La chaîne est lue **de droite à
gauche**, en écartant les sauts qui sont eux-mêmes des proxies déclarés. Lire
la première entrée, comme le montrent la plupart des exemples, laisserait un
attaquant préfixer l'adresse de son choix.

### Activer la vérification en deux étapes

**Paramètres / Vérification en deux étapes.** Le mot de passe seul est le seul
obstacle entre une fuite d'identifiants ailleurs et tous tes secrets, et le
freinage par adresse ne couvre pas ce cas : il suffit de changer d'IP.

Dix codes de secours sont affichés une fois à l'activation. Range-les ailleurs
que sur le téléphone qui porte l'application.

### Borner le journal

Chaque échec de connexion écrit une ligne. Sur un serveur exposé, un disque
plein arrête le serveur sans qu'aucune faille soit nécessaire.

```
synsec serve -audit-retain 8760h
```

Sans cette option le journal est conservé sans limite, ce qui est le bon défaut
à la maison. Les sessions expirées, elles, sont purgées toutes les heures dans
tous les cas.

## Le journal d'audit

Chaque lecture, écriture, partage, connexion et refus est enregistré, avec
l'auteur, l'adresse et l'horodatage. Les valeurs, elles, n'y figurent jamais.

### Le lire

**Journal** dans le menu, section Administration. Trois filtres : une recherche
libre sur le nom d'un compte, d'un secret ou d'un appareil, une action précise,
et une période. Les 200 lignes les plus récentes s'affichent ; la page le dit
quand il y en a davantage.

### Qui peut le lire

Le journal recense ce qui s'est passé dans **tous** les coffres, y compris ceux
que personne ne t'a partagés. Le donner à quiconque porte le drapeau
administrateur reviendrait à annuler, en une page, la séparation des coffres.

Il appartient donc au **compte principal** : le tout premier créé, celui avec
lequel le serveur a été installé. Lui seul le lit d'office, et lui seul décide
de l'ouvrir à d'autres administrateurs, depuis **Journal / Qui peut lire**.

Deux garde-fous : l'accès ne s'ouvre qu'à un administrateur et se referme tout
seul si on lui retire le drapeau ; et le compte principal ne peut pas être
supprimé, sans quoi plus personne ne pourrait jamais rouvrir cette porte.

### En SQL

Pour une requête que l'interface ne sait pas faire, avec n'importe quel client
SQLite :

```sql
SELECT datetime(at, 'unixepoch', 'localtime') AS quand,
       actor_label, action, target, ip
FROM audit_log
ORDER BY at DESC
LIMIT 50;
```

Les lectures y figurent autant que les écritures. Une fois la clé racine
compromise, le chiffrement ne vaut plus rien et la seule question qui reste est
ce que l'intrus a consulté - un journal des seules écritures serait aveugle à
ça.

## Faire tourner une clé de coffre

Si tu soupçonnes qu'une clé a fui :

```
synsec coffre rotation Maison
```

**Toutes les versions de tous les secrets** du coffre sont réchiffrées sous une
clé neuve, en une seule transaction. L'historique y passe aussi : des versions
anciennes qui resteraient lisibles sous l'ancienne clé signifieraient que la
rotation n'a rien rotationné.

Ce qui ne change pas : les valeurs, les identifiants, les jetons des appareils
et les mots de passe des comptes. Rien à reconfigurer nulle part, la rotation
est invisible depuis l'extérieur.

Elle demande la gestion du coffre. Un partage sur un seul secret ne s'étend pas
à sa clé.

Sur un gros coffre, la commande peut prendre quelques secondes : elle
déchiffre et rechiffre chaque version, une par une.

## Le service

```
synsec service status
synsec service uninstall
```

Désinstaller retire le service, pas les données : coffres et secrets restent
intacts.

Sur Windows, le service tourne sous `LocalSystem` et redémarre trois fois après
une panne - à 5 s, 15 s puis 60 s. Sur Linux, l'unité systemd utilise
`Restart=always` avec `RestartSec=5s`, et durcit le processus :
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`.

## Quand ça va mal

### Le serveur ne s'ouvre plus

`/api/v1/health` répond `sealed`, ou le service démarre puis s'arrête. Le
journal dit pourquoi :

```
type C:\ProgramData\SYNSEC\synsec.log
```

Le cas courant est un descellement impossible : machine réinstallée, compte de
service modifié, TPM remis à zéro, ou dossier de données déplacé. La sortie est
toujours la même :

```
synsec recover
```

### Un mot de passe oublié

Un administrateur le réinitialise depuis **Comptes**, ou en ligne de commande
avec le code de récupération :

```
synsec utilisateur passwd cyril
```

Si c'est le mot de passe du **dernier administrateur** qui est perdu, seule la
ligne de commande avec le code de récupération permet de s'en sortir.

### Le code de récupération est perdu

Tant que la machine fonctionne, rien n'est bloqué : SYNSEC continue de
descellier tout seul. Mais tu es à une panne matérielle de tout perdre.

Il n'y a pas de moyen d'en régénérer un : il est dérivé de la clé racine et
n'est stocké nulle part. La sortie, tant que le serveur tourne, est de repartir
d'une installation neuve et d'y recopier tes secrets à la main.

### Un appareil n'accède plus à un secret

Dans l'ordre :

1. Le token est-il révoqué ou expiré ? `synsec token list`.
2. Une restriction d'adresse le vise-t-elle ?
   `synsec secret reseau list <coffre> <secret> -user <toi>`.
3. Le journal d'audit tranche : cherche `access.denied`, le motif y figure.

## Aide-mémoire

```
synsec init                      prépare le serveur, imprime le code
synsec serve                     démarre au premier plan
synsec recover                   rouvre avec le code de récupération

synsec cert trust                fait accepter le certificat
synsec cert show                 emplacement et empreinte

synsec service install           démarrage automatique
synsec service status
synsec service uninstall

synsec utilisateur create|list|passwd|rm
synsec coffre create|list|partager|membres|retirer
synsec secret set|get|list|rm|partager|partages|retirer|reseau
synsec token create|list|revoke
```

Chaque commande accepte `-h`. Les options se placent avant ou après les
arguments, indifféremment.

| Variable | Effet |
|---|---|
| `SYNSEC_DATA_DIR` | dossier de données |
| `SYNSEC_LISTEN` | adresse d'écoute |
| `SYNSEC_SESSION_IDLE` | délai d'inactivité avant déconnexion, par défaut `30m` |
| `SYNSEC_TLS_CERT` | certificat TLS, chaîne complète |
| `SYNSEC_TLS_KEY` | clé privée du certificat |
| `SYNSEC_TRUSTED_PROXIES` | adresses des proxies dont X-Forwarded-For est cru |
| `SYNSEC_WEB_ALLOW` | restreint l'interface web à ces adresses ou blocs CIDR |
| `SYNSEC_AUDIT_RETAIN` | conservation du journal, par exemple `8760h` ; vide = sans limite |
| `SYNSEC_USER` | compte utilisé par les commandes qui touchent un secret |
