# L'agent

`synsec-agent` récupère les secrets d'un coffre et les passe à un programme par
son environnement. C'est le pendant client du serveur : un binaire séparé,
posé sur chaque machine qui consomme un secret.

Le principe : la valeur existe dans la mémoire de l'agent, elle est remise à
l'enfant, et elle disparaît avec lui. Rien n'est écrit dans un fichier que
quelqu'un devra penser à supprimer.

## Installer

Un fichier, aucune dépendance. Depuis les sources :

```
go build -o synsec-agent ./cmd/synsec-agent
```

Pour les autres machines, depuis n'importe quelle plateforme :

```
GOOS=windows GOARCH=amd64 go build -o synsec-agent.exe ./cmd/synsec-agent
GOOS=linux   GOARCH=arm64 go build -o synsec-agent-pi  ./cmd/synsec-agent
GOOS=darwin  GOARCH=arm64 go build -o synsec-agent-mac ./cmd/synsec-agent
```

`arm64` sous Linux couvre le Raspberry Pi 4 et 5 ; un Pi plus ancien veut
`GOARCH=arm GOARM=7`.

## Configurer

Trois valeurs, par variable d'environnement de préférence :

| Variable | Option | Contenu |
|---|---|---|
| `SYNSEC_ADDR` | `-addr` | `https://192.168.1.10:8787` |
| `SYNSEC_TOKEN` | `-token` | le jeton créé pour cet appareil |
| `SYNSEC_CA` | `-ca` | le certificat, si l'autorité n'est pas installée ici |

Le jeton se donne par variable et pas en argument : sous Linux, la ligne de
commande d'un processus est lisible par tous les autres utilisateurs de la
machine.

L'adresse doit être en `https://`. Le serveur n'a pas d'autre mode, et l'agent
refuse `http://` plutôt que d'émettre une requête qui échouera de toute façon.

### Le certificat

SYNSEC émet son propre certificat, donc une machine à qui on ne l'a pas
présenté refuse la connexion - c'est le comportement correct. Deux façons :

```
synsec cert trust                       # sur le serveur, une fois
SYNSEC_CA=/etc/synsec/synsec.crt        # ailleurs, en copiant le .crt
```

`-insecure` existe et désactive la vérification. Il affiche un avertissement à
chaque appel, et il n'a sa place que pendant un dépannage.

## Lancer un programme

```
synsec-agent run -- python bot.py
synsec-agent run -- /usr/bin/node serveur.js
synsec-agent run -prefix APP_ -- ./mon-service
```

Tout ce qui suit `--` appartient au programme lancé, options comprises. Sans le
séparateur, `run -- ls -l` verrait `-l` interprété comme une option de l'agent.

L'agent transmet le code de sortie de l'enfant et lui relaie `Ctrl+C` et
l'arrêt d'un service, donc il s'insère sans rien changer dans une unité systemd
ou une tâche planifiée.

### Les noms de variables

Un identifiant devient une variable en majuscules :

| Secret | Variable |
|---|---|
| `mot_de_passe_mqtt` | `MOT_DE_PASSE_MQTT` |
| `cle-wifi` | `CLE_WIFI` |
| `2fa_seed` | `_2FA_SEED` |

`-prefix APP_` préfixe le tout. Si deux secrets donnaient la même variable -
`mqtt-password` et `mqtt_password` - l'agent s'arrête et les nomme, plutôt que
d'en laisser un gagner silencieusement.

### Quels secrets

Par défaut, tous ceux que le jeton atteint : sa portée décide. `-secret` en
choisit une partie :

```
synsec-agent run -secret mot_de_passe_mqtt,cle_wifi -- ./mon-service
```

Chaque valeur fait une requête. C'est voulu : l'API n'a aucun point d'entrée
qui renvoie un lot de valeurs, parce que chaque lecture est une ligne du
journal d'audit et qu'un appareil qui aspirerait tout d'un coup rendrait ce
journal illisible.

## Les autres commandes

```
synsec-agent list            # ce que ce jeton atteint, sans les valeurs
synsec-agent list -env       # avec le nom de variable en regard
synsec-agent get mqtt_password
eval "$(synsec-agent env)"
```

`get` écrit la valeur brute, sans retour à la ligne, pour être capturée telle
quelle :

```
MDP=$(synsec-agent get mot_de_passe_mqtt)
```

`env` écrit des affectations à évaluer. Formats : `sh` (défaut), `powershell`,
`dotenv`, `json`.

```
eval "$(synsec-agent env)"                      # bash, zsh
synsec-agent env -format powershell | iex       # PowerShell
```

> `env` est moins sûr que `run` : les valeurs passent par le terminal et, selon
> le shell, par son historique. Préfère `run` partout où c'est possible.

## Dans un service

### systemd

```ini
[Service]
Environment=SYNSEC_ADDR=https://192.168.1.10:8787
Environment=SYNSEC_CA=/etc/synsec/synsec.crt
EnvironmentFile=/etc/synsec/token          # SYNSEC_TOKEN=syn_...
ExecStart=/usr/local/bin/synsec-agent run -- /usr/local/bin/mon-service
```

Le fichier de jeton en `chmod 600`, propriété de l'utilisateur du service. Il
ne contient que le jeton : les secrets, eux, ne touchent jamais le disque.

### Windows

Dans une tâche planifiée ou un service, la même chose avec les variables
d'environnement de la tâche :

```
synsec-agent.exe run -- "C:\Program Files\MonApp\app.exe"
```

### Home Assistant

Home Assistant lit `secrets.yaml` plutôt que l'environnement. L'agent n'est pas
le bon outil là : donne-lui le jeton et laisse-le appeler l'API, comme décrit
dans [utilisation.md](utilisation.md).

## Quand ça ne marche pas

| Message | Cause |
|---|---|
| `certificat refusé` | l'autorité n'est pas installée ici : `-ca`, ou `synsec cert trust` |
| `serveur injoignable` | mauvaise adresse, mauvais port, ou serveur arrêté |
| `jeton refusé` | révoqué, expiré, ou mal copié |
| `ce jeton n'a pas accès à ce secret` | hors de sa portée, ou adresse non autorisée |
| `le serveur est verrouillé` | il a redémarré sans pouvoir desceller sa clé |
