# Démonstration

## À faire ce soir, une fois

```
synsec token create "Test Import" "Demo" -secret router_admin -user cyril
```

Coller le jeton dans `jeton.txt`. C'est tout : les deux scripts le lisent.

Vérifier avant d'entrer en salle :

```
.\Lire-Secret.ps1
```

Le certificat de `synsec.synacksys.fr` est publiquement valide, aucune machine
n'a rien à installer.

## Le fil, quinze minutes

**1. Le problème.** Ouvrir le coffre *Test Import*. Neuf secrets qui, chez
tout le monde, vivent en clair dans des `.env` et des `secrets.yaml`, sur des
machines sans journal ni sauvegarde.

**2. La limite, dite avant qu'on la demande.** La clé est descellée
automatiquement au démarrage pour que le serveur reparte seul après une
coupure : un administrateur de cette machine lit donc la base. Ça protège un
disque volé, une sauvegarde volée, un appareil compromis. Pas une machine
compromise. C'est écrit dans le README.

**3. Une intégration ordinaire.**

```
.\Lire-Secret.ps1
```

Montrer le script à l'écran : douze lignes utiles. Puis, dans le navigateur,
la page du secret - la consultation vient d'y apparaître, avec l'heure et
l'adresse.

**4. Le moindre privilège.**

```
.\Lire-Secret.ps1 smtp_password
```

Ce secret existe, ce jeton n'y a pas droit. Refusé, journalisé. Un appareil
compromis ne donne que ce que son jeton portait.

**5. Une application qui ne sait rien de SYNSEC.**

```
agent.cmd
```

Le programme lit `%ROUTER_ADMIN%`. Il n'a ni jeton, ni API, ni ligne de code
modifiée. L'agent va chercher la valeur et la lui remet en mémoire ; elle
disparaît avec le processus.

## Si on te demande

**Combien de temps pour installer ?** Un exécutable, `synsec init`,
`synsec serve`. Aucune dépendance.

**Et si le serveur brûle ?** Un code de récupération imprimé à l'installation
rouvre la base ailleurs. Sauvegarde et code se conservent séparément, et il
faut les deux.

**Vous avez fait tester ?** Analyse statique, et un DAST qui a détruit des
coffres en soumettant des noms absurdes. Ce qui en est sorti : validation des
entrées, effacement réel des pages libérées, mot de passe redemandé avant
toute action irréversible.

**C'est du fait maison.** Oui, et c'est le sujet : pas rivaliser avec un
coffre d'entreprise, montrer que le plancher - chiffrement, journal, moindre
privilège, récupération - est atteignable chez soi.
