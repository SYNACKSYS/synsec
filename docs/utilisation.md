# Utilisation

Ranger ses secrets, les partager, et connecter ses appareils.

## Les trois notions

**Le coffre** regroupe les secrets d'un même usage : « Maison » pour ta
domotique, « Sauvegardes » pour tes clés de restauration. Chaque coffre a sa
propre clé de chiffrement, ce qui veut dire qu'un coffre compromis n'ouvre pas
les autres.

**Le secret** est une entrée, avec deux noms :

- un **nom** que tu écris comme tu veux - « Mot de passe MQTT », accents et
  espaces compris ;
- un **identifiant** technique - `mot_de_passe_mqtt` - par lequel tes appareils
  le demandent.

L'identifiant est proposé à partir du nom et reste modifiable au moment de la
création. Ensuite il ne bouge plus : il fait partie du chiffrement, le changer
voudrait dire tout redéchiffrer. Le nom, lui, se change à volonté sans que rien
ne casse.

**Le token** est ce qu'on donne à une machine. Il ouvre un coffre en lecture ou
en écriture, ne connaît aucun mot de passe, et peut être limité à quelques
secrets précis.

## Dans le navigateur

### Créer un coffre

**+ Nouveau coffre** dans le menu de gauche. Donne-lui un nom que tu
reconnaîtras d'un coup d'œil. Tu en deviens le propriétaire et le gestionnaire.

Le nom fait 60 caractères au maximum. Sont acceptés les lettres accentuées, les
chiffres, les espaces, l'apostrophe, et `- _ . , ( ) [ ] { } @ $ &`. Sont
refusés les deux-points, les barres obliques, les pourcents, les chevrons, les
accents graves, les guillemets et tout caractère de contrôle. La description est
bornée à 200 caractères.

La même règle vaut pour tout ce qu'on écrit et relit ensuite : le nom d'un
secret, le nom d'un appareil, le nom affiché d'un compte. Le nom d'utilisateur,
lui, est plus strict - 32 caractères, lettres non accentuées, chiffres, et
`- _ .` : il se tape à une invite et figure à côté de chaque ligne du journal.

### Retrouver un secret

Le champ en haut du menu de gauche cherche dans **tous les coffres qui te sont
accessibles**, sans que tu aies à te souvenir duquel. Il porte sur le nom
lisible et sur l'identifiant technique, accents ou pas, majuscules ou pas :
`régulateur`, `regulateur` et `RÉGULATEUR` trouvent la même chose.

Les valeurs ne sont pas fouillées. Les chercher voudrait dire déchiffrer chaque
secret de chaque coffre à chaque requête - lent, et exactement le genre de
lecture en masse que le journal d'audit existe pour rendre visible.

Sur la page d'un coffre, le champ **Filtrer cette liste** réduit le tableau
sous tes doigts, sans aller-retour avec le serveur.

### L'apparence

**Paramètres / Apparence** règle deux choses, enregistrées sur ton compte et
donc valables sur tous tes navigateurs :

- la **taille d'affichage**, de 80 à 125 %, l'équivalent du zoom du navigateur
  mais que tu ne réregles pas sur chaque appareil ;
- la **palette**, parmi quatre :

| Palette | Ce que c'est |
|---|---|
| Ardoise | Gris et indigo. Le défaut. |
| Laiton | Zinc et laiton, angles droits. |
| Cuivre | Vert-de-gris et patine. |
| Veilleuse | Fond presque noir, teintes chaudes et éteintes. |

Clair ou sombre suit ton système, **sauf Veilleuse** qui reste sombre en
permanence. C'est délibéré : elle est faite pour la tablette qui reste allumée
dans un couloir, et un thème de veilleuse qui redevient blanc à midi ne sert à
rien.

### Supprimer un coffre

En bas de la page du coffre, réservé à son **propriétaire** : gérer un coffre,
c'est décider qui y entre ; le supprimer emporte les secrets de tous ceux à qui
il a été partagé, et ça ne se délègue pas avec le droit d'ajouter un membre.

Il faut recopier le nom du coffre pour confirmer, ou son identifiant, affiché
sous le champ. L'identifiant rend service quand le nom ne se recopie pas
facilement.

Partent avec lui : les secrets, tout leur historique, les jetons des appareils
et les partages. Il n'y a pas de corbeille - seule une sauvegarde antérieure
les ramène. Le journal d'audit, lui, garde la trace de la suppression.

En ligne de commande :

```
synsec coffre supprimer Maison -confirmer Maison -user cyril
synsec coffre supprimer gfdhugabukzzpbub -confirmer gfdhugabukzzpbub -user cyril
```

### Quand SYNSEC redemande ton mot de passe

Certaines actions te renvoient sur une page « Confirme ton mot de passe » avant
de s'exécuter. Une session ouverte prouve que quelqu'un s'est connecté un jour
sur cette machine ; elle ne prouve pas que c'est toi qui es devant l'écran
maintenant. Pour lire un secret, c'est justement à ça qu'elle sert. Pour
détruire un coffre ou donner accès à quelqu'un, non.

Sont concernées :

- supprimer un coffre, un secret ou un compte ;
- ajouter un membre à un coffre, partager un secret ;
- créer un token d'appareil ou élargir sa portée ;
- réinitialiser le mot de passe de quelqu'un d'autre ;
- ouvrir le journal d'accès.

Ne le sont pas : lire, écrire, et **retirer** un accès. Retirer se refuse mal,
et une demande de mot de passe à chaque clic finit par s'obtenir toute seule.

Une fois confirmé, tu as **cinq minutes** pour enchaîner sans qu'on te le
redemande - le temps de faire le ménage dans plusieurs coffres. La déconnexion
et le redémarrage du serveur ferment cette fenêtre. L'action que tu avais
demandée n'a pas été exécutée : reviens sur la page et relance-la.

### Reprendre ce que tu as déjà

Personne ne recopie trente secrets à la main. Si tes mots de passe sont
aujourd'hui dans un `secrets.yaml` de Home Assistant ou dans un `.env`, le
bouton **Importer** sur la page du coffre ouvre un formulaire : tu choisis le
fichier, et un compte rendu te dit ce qui a été créé, ligne par ligne.

Le fichier n'est ni conservé ni recopié sur le serveur : il est lu, les valeurs
sont chiffrées, et il n'en reste rien.

En ligne de commande, avec un aperçu avant écriture :

```
synsec import Maison secrets.yaml -essai
synsec import Maison secrets.yaml
```

Le premier appel montre ce qui serait créé, sans rien écrire. Chaque clé
devient un secret : la clé telle quelle sert de nom lisible, sa version en
identifiant technique sert aux appareils. `mqtt_password` reste
`mqtt_password`, `MQTT Password` devient `mqtt_password`.

Ce que l'import refuse plutôt que de deviner :

- un fichier **imbriqué**, avec des niveaux - ce n'est pas la forme d'un
  `secrets.yaml`, et inventer des noms pour ses branches créerait des secrets
  que tu n'as pas demandés ;
- une **clé en double**, qui ferait perdre l'une des deux valeurs sans le dire ;
- **deux clés qui donnent le même identifiant**, par exemple `mqtt-password` et
  `mqtt_password`.

Un identifiant déjà présent dans le coffre est ignoré. Relancer un import ne
doit pas écrire en silence une seconde version de tout. Pour écraser
délibérément, ajoute `-remplacer`.

Les valeurs ne sont jamais affichées, ni dans l'aperçu ni après.

> Le fichier d'origine n'est ni modifié ni effacé. **C'est à toi de le
> supprimer** une fois l'import vérifié : tant qu'il est là, il contient
> toujours tout, en clair.

### Ajouter un secret

Ouvre le coffre, puis **Ajouter un secret**.

- **Nom** : « Mot de passe MQTT ».
- **Identifiant** : proposé au fur et à mesure de la frappe, `mot_de_passe_mqtt`.
  Laisse-le tel quel dans le doute.
- **Valeur** : le mot de passe ou la clé. Le bouton **Générer une valeur** en
  tire une pour toi - trente-deux lettres et chiffres, soit cent quatre-vingt-dix
  bits. Le même bouton existe sur un secret déjà créé, pour le renouveler.

Le tirage se fait dans ton navigateur, pas sur le serveur : la valeur ne
traverse le réseau qu'une fois, à l'enregistrement, au lieu d'un aller-retour
supplémentaire.

Pas de symboles, délibérément. Ces valeurs finissent dans un `secrets.yaml` ou
une variable d'environnement, où le dollar, l'antislash et les guillemets
changent de sens - et la panne se manifeste des jours plus tard, dans un
appareil qui ne démarre plus. La longueur compense largement l'alphabet plus
court.

La liste d'un coffre n'affiche jamais une valeur - seulement les noms, les
identifiants et les versions. Ouvrir un secret le déchiffre, et cette
consultation est enregistrée dans le journal.

### Modifier

**Modifier** sur la ligne du secret. Enregistrer crée une **nouvelle version** :
l'ancienne valeur reste dans l'historique, elle n'est pas écrasée.

Le nom se change librement. L'identifiant est en lecture seule - pour en
changer, crée le secret sous un nouvel identifiant puis supprime l'ancien.

### Revenir à une valeur précédente

Sous le formulaire, la section **Historique** liste les versions : leur numéro,
leur date, et qui les a écrites. Le bouton **Rétablir** ramène une ancienne
valeur.

Rien n'est effacé. Revenir à la version 2 écrit une **version 5** contenant la
même valeur : l'historique reste complet, et le journal d'audit garde la trace
du retour en arrière. Un retour silencieux, qui réécrirait le passé, serait
précisément ce qu'un journal est censé empêcher.

Les valeurs anciennes ne s'affichent pas dans la liste. Les montrer voudrait
dire les déchiffrer toutes à l'ouverture de la page, ce qui reviendrait à lire
bien plus que ce qui a été demandé.

En ligne de commande :

```
synsec secret versions Maison mot_de_passe_mqtt
synsec secret revenir  Maison mot_de_passe_mqtt 2
```

### Qui a ouvert ce secret

Plus bas sur la même page, la section **Qui l'a ouvert** montre les dernières
consultations : la date, le compte ou l'appareil, l'adresse d'où ça venait, et
si c'était refusé. Ta propre visite est en haut de la liste, puisque l'ouvrir
compte comme une consultation.

Ce qui se lit là-dedans : un appareil qui vient toutes les cinq minutes, c'est
sa routine. Le même nom à trois heures du matin depuis une adresse que tu ne
reconnais pas, ou une ligne **refusé** que tu n'expliques pas, méritent une
question.

Réservé aux **gestionnaires** du coffre. Voir qui consulte un secret, c'est
voir qui y a accès, et ça ne regarde pas quelqu'un à qui on a simplement
confié une valeur.

La liste s'arrête aux vingt-cinq dernières lignes. Pour remonter plus loin, ou
pour croiser plusieurs coffres, c'est le journal d'audit complet - réservé au
compte principal.

### Partager

Deux niveaux, selon ce que tu veux ouvrir.

**Tout un coffre** - bouton **Membres** :

| Accès | Permet |
|---|---|
| Lecture | consulter les valeurs |
| Écriture | les modifier, en ajouter, en supprimer |
| Gestion | tout cela, plus donner accès aux autres |

**Un seul secret** - bouton **Partager** sur sa ligne. La personne y accède, et
à rien d'autre : le coffre reste invisible pour elle, il apparaît seulement dans
sa section « Secrets partagés avec moi ».

Un partage de secret n'autorise jamais la suppression. Confier un mot de passe
ne donne pas le pouvoir de le détruire.

Et personne ne peut repasser à un tiers ce qu'on lui a confié : donner accès est
toujours un droit de gestionnaire du coffre. Ton mot de passe est redemandé au
passage, comme pour toute action qui ouvre un accès.

### Ta page d'accueil

Trois sections, selon la provenance :

- **Mes coffres** - ceux que tu as créés.
- **Coffres partagés avec moi** - ceux de quelqu'un d'autre, avec son nom et ton
  niveau d'accès. Ils y restent même si tu y es gestionnaire : un coffre créé
  par Alice reste le sien.
- **Secrets partagés avec moi** - des entrées isolées, confiées une par une.

### Changer ton mot de passe

**Paramètres / Mot de passe**, ou la petite clé en bas du menu, à côté du bouton
de déconnexion. L'actuel est demandé : un navigateur laissé ouvert ne suffit
donc pas à te verrouiller hors de ton compte. Le changement ferme tes sessions
ouvertes ailleurs et garde celle-ci.

### Régler l'affichage

**Paramètres / Apparence** dans le menu de gauche. La taille d'affichage va de
80 % à 125 % : c'est l'équivalent du zoom du navigateur, mais enregistré sur ton
compte, donc valable sur tous les appareils où tu te connectes. Le réglage
n'appartient qu'à toi, il ne change rien pour les autres.

## Connecter un appareil

### Créer le token

```
synsec token create Maison "Home Assistant"
```

Le token s'affiche **une seule fois**, avec la commande prête à coller pour le
tester. Copie-le tout de suite : il n'est stocké que sous forme d'empreinte, et
personne - pas même toi - ne peut le retrouver ensuite. Un token perdu se
remplace, il ne se récupère pas.

Options utiles :

```
synsec token create Maison "Sauvegarde" -write
synsec token create Maison "HA" -expires 720h
synsec token create Maison "HA" -ip 192.168.1.72
synsec token create Maison "HA" -secret mot_de_passe_mqtt,cle_zigbee
```

`-write` autorise l'écriture, absent le token est en lecture seule. `-expires`
prend une durée Go (`720h` = 30 jours), absent le token n'expire pas. `-ip`
accepte des adresses et des blocs CIDR séparés par des virgules.

### La portée d'un token

Par défaut un token atteint **tout le coffre**. `-secret` le limite à une liste
d'identifiants : il n'atteint plus qu'eux, et le reste du coffre lui répond
403 - y compris la liste, qui ne nomme que ce qu'il peut lire.

Un secret créé après coup **ne rejoint pas** une portée existante. C'est
délibéré : un identifiant qui s'élargit tout seul est celui que plus personne
ne relit.

La portée se change sans redonner de jeton, depuis le bouton **Portée** sur la
ligne de l'appareil, ou en ligne de commande :

```
synsec token portee <identifiant>
synsec token portee <identifiant> mot_de_passe_mqtt,cle_zigbee -user cyril
synsec token portee <identifiant> "" -user cyril
```

Sans liste, la commande affiche la portée actuelle et ne demande rien. Avec une
liste, elle change ce qu'un appareil atteint : ton mot de passe est demandé, et
il faut gérer le coffre. Une liste vide rend le coffre entier.

### Lire un secret

```
curl -H "Authorization: Bearer syn_..." \
     "https://ton-serveur:8787/api/v1/secrets/value?name=mot_de_passe_mqtt"
```

```json
{"name":"mot_de_passe_mqtt","value":"s3cr3t"}
```

Le token se présente **uniquement** dans l'en-tête `Authorization`. Il n'est
jamais accepté dans l'URL : une adresse finit dans les journaux de proxy et
l'historique du navigateur, ce qui est exactement là où un secret ne doit pas
être.

### Les autres appels

| Appel | Effet |
|---|---|
| `GET /api/v1/health` | état du serveur, sans authentification |
| `GET /api/v1/secrets` | les identifiants du coffre, sans aucune valeur |
| `GET /api/v1/secrets/value?name=...` | lit une valeur |
| `PUT /api/v1/secrets/value?name=...` | écrit une valeur, corps `{"value":"..."}` |
| `DELETE /api/v1/secrets/value?name=...` | supprime le secret et son historique |

Un secret se demande **un par un**. Rien ne renvoie un lot de valeurs : c'est
un choix, pas un manque.

### Restreindre un secret à une adresse

Indépendamment du token, un secret peut n'être lisible que depuis certaines
adresses :

```
synsec secret reseau add Maison zigbee_cle 192.168.1.72 -user cyril
synsec secret reseau add Maison zigbee_cle 192.168.1.0/24 -user cyril
```

La restriction appartient au secret : elle vaut quel que soit le token
présenté, et elle couvre la lecture, l'écriture et la suppression. Elle ne
concerne que les appels des appareils - l'interface web et la ligne de commande
demandent ton mot de passe, ce qui est une preuve d'identité là où l'adresse ne
fait qu'identifier une machine.

Un identifiant qui n'existe pas encore n'est pas bloqué : une liste d'adresses
écrite pour un secret ne gouverne pas la création d'un autre.

> Dès la première adresse ajoutée, plus aucun appareil ne peut lire ce secret
> depuis une autre. Pense à `127.0.0.1` si un service tourne sur ce serveur.

Pour voir ou lever une restriction :

```
synsec secret reseau list Maison zigbee_cle -user cyril
synsec secret reseau rm Maison zigbee_cle 192.168.1.72 -user cyril
```

Gérer ces adresses demande la gestion du coffre - personne ne peut donc
s'enfermer dehors, un gestionnaire retire toujours une restriction.

## En ligne de commande

Les commandes qui touchent un secret demandent ton mot de passe et appliquent
exactement les mêmes droits que l'interface web. Indique le compte avec
`-user`, ou pose la variable une fois pour la session :

```
set SYNSEC_USER=cyril
```

### Lire et écrire

```
synsec secret list Maison
synsec secret get Maison mot_de_passe_mqtt
synsec secret set Maison mot_de_passe_mqtt
synsec secret set Maison cle_wifi -label "Clé Wi-Fi du salon"
```

Sans `-value`, la valeur est lue sur l'entrée standard. C'est volontaire :
passée en argument, elle resterait dans l'historique du shell et, sous Linux,
dans la liste des processus visible par les autres utilisateurs.

`secret get` écrit la valeur brute, sans retour à la ligne, pour être
directement redirigée :

```
synsec secret get Maison mot_de_passe_mqtt > /tmp/mqtt.txt
```

### Partager

```
synsec coffre partager Maison alice -role lecture -user cyril
synsec coffre membres Maison
synsec coffre retirer Maison alice

synsec secret partager Maison mot_de_passe_mqtt alice -role lecture -user cyril
synsec secret partages Maison mot_de_passe_mqtt
synsec secret retirer Maison mot_de_passe_mqtt alice
```

Les rôles s'écrivent en français - `lecture`, `écriture`, `gestion` - ou sous
leur nom stocké - `reader`, `writer`, `manager`.

Donner un accès demande ton mot de passe et le droit de **gestion** sur le
coffre, exactement comme dans le navigateur : la ligne de commande tourne à
côté de la base, ce n'est pas une raison pour que ce soit le chemin le plus
court vers le coffre de quelqu'un d'autre. Le journal retient ton nom de
compte. Retirer un accès ne demande rien.

### Les tokens

```
synsec token list
synsec token list Maison
synsec token portee <identifiant>
synsec token portee <identifiant> mot_de_passe_mqtt -user cyril
synsec token revoke <identifiant>
```

La liste montre la portée de chaque appareil : le nom des secrets qu'il
atteint, ou « tout le coffre ».

Créer un token ou **changer** sa portée demande ton mot de passe et le droit de
gestion : un token est un accès permanent, sans mot de passe, depuis n'importe
où sur le réseau. Le lire et le révoquer ne demandent rien.

Un token révoqué reste dans la liste, marqué comme tel : le journal d'audit
continue de pointer vers quelque chose qui a un nom.

## Home Assistant

Dans `secrets.yaml` :

```yaml
synsec_token: "Bearer syn_..."
```

Le mot **Bearer fait partie de la valeur**. Home Assistant remplace un
`!secret` en entier et ne peut rien ajouter devant ; sans lui, l'API refuse la
requête et le capteur reste vide sans dire pourquoi.

Puis un capteur REST qui va chercher la valeur au démarrage :

```yaml
rest:
  - resource: "https://ton-serveur:8787/api/v1/secrets/value?name=mot_de_passe_mqtt"
    headers:
      Authorization: !secret synsec_token
    sensor:
      - name: "MQTT password"
        value_template: "{{ value_json.value }}"
```

Home Assistant doit faire confiance au certificat de SYNSEC : copie
`synsec.crt` depuis le dossier de données vers son magasin, ou installe-le au
niveau du système sur la machine qui l'héberge.

### Le sens inverse : SYNSEC prévient Home Assistant

Ce qui précède, c'est Home Assistant qui vient chercher un secret. SYNSEC sait
aussi faire l'inverse : envoyer un message à Home Assistant quand quelque chose
sort de l'ordinaire, un appareil refusé par exemple. Ça se règle dans
**Paramètres / Alertes** et c'est décrit dans
[administration.md](administration.md#être-prévenu).
