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

### Supprimer un coffre

En bas de la page du coffre, réservé à son **propriétaire** : gérer un coffre,
c'est décider qui y entre ; le supprimer emporte les secrets de tous ceux à qui
il a été partagé, et ça ne se délègue pas avec le droit d'ajouter un membre.

Il faut recopier le nom du coffre pour confirmer. Partent avec lui : les
secrets, tout leur historique, les jetons des appareils et les partages. Il n'y
a pas de corbeille - seule une sauvegarde antérieure les ramène. Le journal
d'audit, lui, garde la trace de la suppression.

En ligne de commande :

```
synsec coffre supprimer Maison -confirmer Maison
```

### Ajouter un secret

Ouvre le coffre, puis **Ajouter un secret**.

- **Nom** : « Mot de passe MQTT ».
- **Identifiant** : proposé au fur et à mesure de la frappe, `mot_de_passe_mqtt`.
  Laisse-le tel quel dans le doute.
- **Valeur** : le mot de passe ou la clé.

La liste d'un coffre n'affiche jamais une valeur - seulement les noms, les
identifiants et les versions. Ouvrir un secret le déchiffre, et cette
consultation est enregistrée dans le journal.

### Modifier

**Modifier** sur la ligne du secret. Enregistrer crée une **nouvelle version** :
l'ancienne valeur reste dans l'historique, elle n'est pas écrasée.

Le nom se change librement. L'identifiant est en lecture seule - pour en
changer, crée le secret sous un nouvel identifiant puis supprime l'ancien.

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
toujours un droit de gestionnaire du coffre.

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
synsec token portee <identifiant> mot_de_passe_mqtt,cle_zigbee
synsec token portee <identifiant> ""
```

Sans liste, la commande affiche la portée actuelle. Avec une liste vide, elle
rend le coffre entier.

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
présenté. Elle ne concerne que les appels des appareils - l'interface web et la
ligne de commande demandent ton mot de passe, ce qui est une preuve d'identité
là où l'adresse ne fait qu'identifier une machine.

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
synsec coffre partager Maison alice -role lecture
synsec coffre membres Maison
synsec coffre retirer Maison alice

synsec secret partager Maison mot_de_passe_mqtt alice -role lecture
synsec secret partages Maison mot_de_passe_mqtt
synsec secret retirer Maison mot_de_passe_mqtt alice
```

Les rôles s'écrivent en français - `lecture`, `écriture`, `gestion` - ou sous
leur nom stocké - `reader`, `writer`, `manager`.

### Les tokens

```
synsec token list
synsec token list Maison
synsec token portee <identifiant>
synsec token revoke <identifiant>
```

La liste montre la portée de chaque appareil : le nom des secrets qu'il
atteint, ou « tout le coffre ».

Un token révoqué reste dans la liste, marqué comme tel : le journal d'audit
continue de pointer vers quelque chose qui a un nom.

## Home Assistant

Dans `secrets.yaml` :

```yaml
synsec_token: "syn_..."
```

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
