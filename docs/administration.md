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

### Ce qui demande le mot de passe une seconde fois

Deux familles d'actions ne se contentent pas d'une session ouverte : celles qui
ne se défont pas, et celles qui **donnent** un accès. Supprimer un coffre, un
secret ou un compte ; ajouter un membre ; partager un secret ; créer un token
ou élargir sa portée ; réinitialiser le mot de passe de quelqu'un ; ouvrir le
journal d'accès.

Dans le navigateur, SYNSEC affiche une page de confirmation, puis laisse cinq
minutes avant de redemander. En ligne de commande, ces mêmes actions exigent
`-user` et le mot de passe du compte, et vérifient le rôle sur le coffre : la
ligne de commande tourne à côté de la base, ce n'est pas une raison pour qu'elle
soit le chemin court. Le journal nomme le compte, jamais « cli ».

Retirer un accès - révoquer un token, retirer un membre ou un partage - ne
demande rien : ça échoue du bon côté, et une demande de mot de passe à chaque
clic finit par s'obtenir toute seule.

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

### Ou une clé de sécurité

**Paramètres / Clé de sécurité.** Une YubiKey, une SoloKey, Windows Hello, une
Touch ID : tout ce qui parle FIDO2. Branche, touche, c'est fait.

Une clé n'est pas seulement plus commode qu'un code, elle est plus solide sur
un point précis. Ce qu'elle signe contient l'adresse du serveur. Une page qui
imite SYNSEC pour récolter des identifiants n'obtient rien d'une clé, là où un
code à six chiffres tapé sur cette page lui aurait été donné - et six chiffres
restent valables trente secondes, ce qui suffit largement.

Trois algorithmes sont acceptés, ce qui couvre tout ce qui se vend : ES256 sur
les clés FIDO2, RS256 sur les Windows Hello adossés à un TPM plus ancien, et
Ed25519. L'attestation - la preuve de marque et de modèle - n'est ni demandée
ni vérifiée : elle répond à « quelle est cette clé », pas à « cette clé est-elle
la tienne », et celui qui l'enregistre est déjà connecté.

Deux limites à connaître :

- **Il faut un nom de machine.** Le navigateur refuse d'enregistrer une clé sur
  une adresse IP. `https://synsec.maison:8787` fonctionne, `https://192.168.1.20:8787`
  non. Une ligne dans le fichier `hosts`, ou une entrée sur le routeur, suffit.
- **Une clé est liée à ce nom.** Enregistrée depuis `synsec.maison`, elle ne
  répondra pas à `synsec` tout court. Choisis un nom et tiens-t'y, ou enregistre
  une clé par nom.

Plusieurs clés peuvent cohabiter, avec ou sans l'application. Enregistres-en
deux si tu peux, et range la seconde ailleurs.

Enregistrer la première clé d'un compte génère les codes de secours si le compte
n'en a pas : sans eux, perdre l'objet ferme le compte définitivement. Retirer
l'application d'un compte qui garde une clé conserve ces codes, pour la même
raison.

### L'imposer à tout le monde

Les deux réglages ci-dessus sont le choix de chacun. Sur un serveur exposé, ce
n'est pas suffisant : le compte qui n'a qu'un mot de passe est celui qui tombe
le jour où ce mot de passe fuite ailleurs, et c'est rarement celui de la
personne qui a lu cette page.

Deux façons de l'activer, selon qui doit pouvoir revenir dessus.

**Depuis l'interface.** *Sécurité du serveur*, dans la section Administration.
Réservée au compte principal, comme le journal : c'est une règle sur tout le
monde, pas une préférence. Le choix est enregistré et survit à un redémarrage.

L'activation est refusée si ton propre compte n'a pas encore de second
facteur - elle t'enfermerait aussitôt hors de tes coffres.

**Depuis la ligne de commande.** Elle a le dernier mot, dans les deux sens :

```
synsec serve -require-2fa
```

Ainsi fixée, aucun administrateur ne peut la relâcher depuis un navigateur ;
la page affiche l'état sans proposer de le changer. Et dans l'autre sens :

```
synsec serve -require-2fa=false
```

C'est la porte de sortie du serveur dont le seul compte s'est enfermé hors de
sa propre règle. Le `=` est obligatoire : `-require-2fa false` laisserait la
valeur être lue comme l'option suivante.

Sans mention de l'option, c'est l'interface qui décide.
`SYNSEC_REQUIRE_2FA` accepte `1` ou `0` et se comporte pareil.

La connexion continue de fonctionner - sans quoi personne ne pourrait
s'enrôler - mais la session n'atteint que **Vérification en deux étapes** et
**Clé de sécurité**. Toute autre page renvoie là, formulaires compris : une
écriture postée depuis un onglet resté ouvert avant l'activation ne passe pas.
La barre latérale se réduit aux deux pages qui mènent dehors.

L'une des deux méthodes suffit. Retirer le dernier facteur est refusé avec sa
raison, plutôt qu'accepté puis défait à la requête suivante.

**Ce que ça ne couvre pas.** Les jetons de service. Un appareil ne peut rien
détenir de plus que son jeton, et ce jeton est déjà 256 bits tirés au hasard :
c'est la restriction d'adresse et la portée par secret qui l'encadrent, pas un
second facteur. La ligne de commande non plus - elle s'exécute sur la machine,
où quiconque peut l'atteindre a déjà la clé racine.

**En service.** `synsec service install` inscrit dans la définition du service
toutes les options qu'on lui passe - ce sont exactement celles de
`synsec serve`. Pour les changer ensuite, réinstalle le service :

```
sudo synsec service uninstall
sudo synsec service install -web-allow 192.168.1.0/24 -require-2fa
```

**Avant de l'activer.** Préviens les comptes qui existent. Ils ne pourront plus
rien faire tant qu'ils n'auront pas enrôlé quelque chose, et une clé exige un
nom de machine (voir plus haut) - depuis une adresse IP, il ne leur restera que
l'application.

### Borner le journal

Chaque échec de connexion écrit une ligne. Sur un serveur exposé, un disque
plein arrête le serveur sans qu'aucune faille soit nécessaire.

```
synsec serve -audit-retain 8760h
```

Sans cette option le journal est conservé sans limite, ce qui est le bon défaut
à la maison. Les sessions expirées, elles, sont purgées toutes les heures dans
tous les cas.

### Le freinage de l'API, sans réglage

L'interface web freinait déjà les tentatives de connexion ; l'API, elle, ne
freinait rien. Ce n'est pas le jeton qui est en jeu - un secret de 256 bits
tirés au hasard ne se devine pas - mais tout ce qui l'entoure : chaque appel
coûte une lecture de base, chaque échec contre un identifiant connu coûte une
ligne de journal, et il en faut peu pour remplir un disque ou noyer les lignes
qui auraient dû se voir.

Chaque adresse dispose donc de **30 appels d'un coup**, puis de **2 par
seconde**. Un démarrage d'Home Assistant qui va chercher une poignée de secrets
passe sans rien sentir ; un balayage est refusé avec un `429` et un en-tête
`Retry-After`. Le freinage est vérifié **avant** l'authentification, si bien
qu'un flot de requêtes non authentifiées ne touche jamais la base.

Rien à activer : c'est le comportement par défaut, à la maison comme ailleurs.

## Effacer ce qui a été supprimé

Une suppression écrase désormais ce qu'elle libère : SQLite est configuré en
`secure_delete`, donc les pages rendues au fichier sont remises à zéro plutôt
que simplement marquées réutilisables.

Ça ne vaut que pour les suppressions faites depuis. **Ce qui a été supprimé
avant est toujours dans le fichier** : un secret effacé, un coffre supprimé,
ou les anciens chiffrés qu'une rotation de clé a remplacés. Rien de tout cela
n'est en clair - c'est du chiffré, comme le reste de la base - mais c'est
lisible avec la clé du coffre, ce qui vide de son sens la rotation faite
justement parce qu'on soupçonnait cette clé.

Pour nettoyer, serveur arrêté :

```
net stop SYNSEC
synsec maintenance nettoyer
net start SYNSEC
```

La commande vérifie l'intégrité de la base, replie le journal d'écriture,
réécrit le fichier, et annonce la taille avant et après. Elle refuse de
réécrire une base dont l'intégrité est douteuse : dans ce cas c'est une
sauvegarde qu'il faut restaurer, pas un nettoyage qu'il faut lancer.

Une limite honnête : SYNSEC réécrit son fichier, il ne contrôle pas ce que le
système de fichiers ou le disque conservent de l'ancien. Sur un SSD, seul le
chiffrement du disque répond à cette question.

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

Une exception, étroite : la page d'un secret montre ses vingt-cinq dernières
consultations à qui **gère le coffre**. C'est le journal réduit à une seule
ligne de la base, sans rien du reste du serveur, et ça répond à la question que
se pose la personne responsable d'un secret plutôt qu'à celle de l'opérateur.
Chaque entrée porte désormais le coffre concerné, pour que deux coffres ayant
un secret du même nom ne se mélangent jamais.

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

## Être prévenu

Le journal enregistre tout, mais un journal ne réveille personne. SYNSEC peut
envoyer un message quand quelque chose sort de l'ordinaire.

**Paramètres / Alertes**, réservé au compte principal comme le journal : ce qui
est annoncé traverse tous les coffres, et l'adresse à qui c'est annoncé est un
endroit où les noms de tes secrets finissent.

### Ce qui déclenche

Trois niveaux, à choisir selon ce que tu veux voir arriver sur ton téléphone.

| Niveau | Ce qui part |
|---|---|
| **Critique** | appareil refusé par le filtrage d'adresse, accès refusé, coffre ou secret supprimé, serveur rouvert avec le code de récupération, adresse bloquée après trop de mots de passe ratés |
| **Avertissement** | tout ce qui précède, plus : accès donné à un coffre, secret partagé, appareil créé ou élargi, compte créé ou supprimé, second facteur retiré, règle du serveur modifiée |
| **Tout** | tout ce qui précède, plus : mots de passe ratés, imports, adresses jamais vues, retours à une version précédente |

Les lectures ordinaires ne partent jamais, à aucun niveau. Une maison en fait
quelques milliers par semaine, et une notification à cette fréquence est une
notification que plus personne ne lit. La question « qui a ouvert ce secret »
se lit sur la page du secret.

**Adresse jamais vue** mérite une explication. SYNSEC retient les adresses d'où
chaque compte et chaque appareil se manifestent. La toute première est apprise
en silence : un appareil doit bien parler de quelque part la première fois.
Celles d'après sont signalées. Ton téléphone sur le wifi du bureau, c'est ça.
Ton appareil domotique depuis une adresse à l'autre bout du monde, c'est ça
aussi, et c'est toi qui fais la différence.

### Où ça part

Un POST JSON à l'adresse de ton choix : Home Assistant, ntfy, Gotify, un salon
Discord, ou ton propre script. Aucun service tiers, aucun quota.

```
synsec alertes webhook https://domotique.maison:8123/api/webhook/synsec -user cyril
synsec alertes niveau avertissement -user cyril
synsec alertes activer -user cyril
synsec alertes test -user cyril
```

L'adresse et la clé de signature sont **chiffrées avec la clé racine**, comme
un secret : une URL Discord ou ntfy est elle-même un mot de passe. Conséquence
assumée : un serveur scellé n'envoie rien, puisqu'il ne peut pas les lire. Il
ne sert plus aucun secret non plus, il n'a donc rien à raconter.

### Vérifier que le message vient bien de SYNSEC

Chaque envoi porte deux en-têtes :

```
X-SYNSEC-Timestamp: 1785380047
X-SYNSEC-Signature: sha256=4f3c...
```

La signature couvre l'horodatage **et** le corps, pour qu'un message capté une
fois ne puisse pas être rejoué plus tard :

```
signature = "sha256=" + hmac_sha256(clé, horodatage + "." + corps)
```

En Python, côté réception :

```python
import hmac, hashlib

def valide(cle, entetes, corps):
    attendu = "sha256=" + hmac.new(
        cle.encode(),
        (entetes["X-SYNSEC-Timestamp"] + ".").encode() + corps,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(attendu, entetes["X-SYNSEC-Signature"])
```

Sans cette vérification, n'importe quoi capable d'atteindre ton destinataire
peut inventer une alerte, ou noyer une vraie sous cent fausses.

### Recevoir dans Home Assistant

Une automatisation déclenchée par webhook. L'identifiant que tu mets dans
`webhook_id` est la fin de l'adresse à donner à SYNSEC.

```yaml
automation:
  - alias: "Alerte SYNSEC"
    trigger:
      - platform: webhook
        webhook_id: synsec_7f3a9c1e4b8d2a6f
        allowed_methods: [POST]
        local_only: true
    action:
      - service: notify.mobile_app_telephone
        data:
          title: "SYNSEC : {{ trigger.json.events[0].severity }}"
          message: >
            {{ trigger.json.events[0].summary }}
            {% if trigger.json.events[0].count > 1 %}
            ({{ trigger.json.events[0].count }} fois)
            {% endif %}
          data:
            importance: >
              {{ 'high' if trigger.json.events[0].severity == 'critique' else 'default' }}
```

Côté SYNSEC :

```
synsec alertes webhook http://homeassistant.local:8123/api/webhook/synsec_7f3a9c1e4b8d2a6f -user cyril
synsec alertes test -user cyril
```

Trois choses à savoir.

**`local_only: true`** limite l'appel au réseau local. À garder : c'est la
seule vérification que Home Assistant sait faire tout seul.

**La signature ne se vérifie pas en Jinja.** Home Assistant n'a pas de filtre
HMAC dans ses modèles, donc l'en-tête `X-SYNSEC-Signature` ne peut pas y être
contrôlé sans passer par pyscript ou AppDaemon. Dans cette configuration, c'est
l'identifiant du webhook qui fait office de secret : prends-en un long et
aléatoire, comme ci-dessus, et ne le mets pas dans une capture d'écran.

**En `http://` sur le réseau local**, ça marche tel quel. Si ton Home Assistant
est en `https://` avec un certificat auto-signé, l'envoi échoue avec « destinataire
injoignable » : SYNSEC vérifie les certificats et n'a pas d'exception à offrir.

Un message porte plusieurs événements quand plusieurs choses arrivent en même
temps. L'exemple ci-dessus n'affiche que le premier ; pour tous les traiter,
boucle sur `trigger.json.events` avec `repeat`.

### Ce qui empêche l'inondation

C'est la partie qui décide si le système est utilisable. Un balayage
automatique produit des milliers de refus en deux minutes.

- Les événements identiques sont **regroupés** : un seul message, avec le
  nombre (« 1 847 fois »).
- Un même type ne repart pas plus d'**une fois par minute**. Ce qui arrive
  entre-temps s'accumule et part avec le message suivant.
- **200 messages par jour** au maximum. Le plafond atteint, SYNSEC le dit une
  fois puis se tait jusqu'au lendemain. Le journal, lui, continue de tout
  enregistrer.

### Ce qui ne part jamais

La valeur d'un secret. Ni ici, ni dans le journal dont ces messages sont tirés.
Le nom du coffre et celui du secret, en revanche, oui : le message va chez toi,
et une alerte qui ne dit pas de quoi elle parle ne sert à rien.

### Une commande lancée pendant l'arrêt du serveur

Les alertes suivent le journal, pas les gestionnaires de l'interface. Une
suppression faite en ligne de commande, service arrêté, est signalée au
redémarrage suivant - ce qui est précisément le cas qu'un branchement dans les
pages web aurait manqué.

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
synsec coffre create|list|supprimer|partager|membres|retirer|rotation
synsec secret set|get|list|rm|partager|partages|retirer|reseau
synsec token create|list|portee|revoke
synsec maintenance nettoyer      compacte la base, efface les pages libérées
synsec alertes                   webhook|niveau|activer|desactiver|test
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
| `SYNSEC_USER` | compte utilisé par les commandes qui touchent un secret ou donnent un accès |
