# SYNSEC

Serveur de secrets pour la maison. Un binaire unique, pas de base de données à
installer, pas de runtime à maintenir : tes mots de passe et tes clés restent
chez toi, chiffrés, et tes appareils viennent les chercher tout seuls.

Pensé pour un particulier qui fait de la domotique - Home Assistant, Zigbee,
MQTT, scripts de sauvegarde - plutôt que pour une entreprise.

## Ce que ça fait

- **Un coffre par usage.** « Maison », « Sauvegardes », « Bureau ». Chaque
  coffre a sa propre clé de chiffrement.
- **Un secret est une entrée** avec un nom lisible et un identifiant technique.
  Tu écris « Mot de passe MQTT », tes appareils demandent `mot_de_passe_mqtt`.
- **Une interface web** pour les humains, une **API REST** pour les machines,
  une **ligne de commande** pour l'administration.
- **Chacun ne voit que ce qui lui appartient** ou ce qu'on lui a partagé -
  l'administrateur du serveur compris.
- **Démarrage automatique** en service Windows ou unité systemd, sans que
  personne ait à saisir quoi que ce soit après une coupure de courant.

## Démarrage rapide

```
synsec init
synsec cert trust
synsec utilisateur create cyril
synsec service install
```

Puis ouvre `https://<nom-de-ta-machine>:8787/`.

Les quatre commandes sont détaillées dans [l'installation](docs/installation.md).

## Documentation

| Document | Pour |
|---|---|
| [Installation](docs/installation.md) | Poser SYNSEC sur une machine et le faire démarrer seul |
| [Utilisation](docs/utilisation.md) | Ranger ses secrets, les partager, connecter un appareil |
| [Administration](docs/administration.md) | Comptes, sauvegarde, récupération, rotation des clés |
| [L'agent](docs/agent.md) | Injecter les secrets dans un programme, sur Windows, Linux et macOS |

## Ce que la sécurité couvre, et ce qu'elle ne couvre pas

À lire avant de confier quoi que ce soit d'important.

**Couvert.** Les valeurs sont chiffrées en XChaCha20-Poly1305 sous une clé par
coffre, elle-même scellée par une clé racine que le système d'exploitation
protège. Un disque volé, une sauvegarde égarée ou un dump de la base sont
inexploitables. Chaque lecture et chaque écriture laissent une trace nominative
dans le journal d'audit.

**Non couvert.** La clé racine est déscellée automatiquement au démarrage -
c'est ce qui permet à ta box domotique de redémarrer à trois heures du matin
sans personne. Un administrateur du système d'exploitation peut donc obtenir la
même clé et lire la base. Le cloisonnement entre comptes est une règle
appliquée par SYNSEC, pas une barrière cryptographique.

Si tu as besoin qu'un administrateur système ne puisse pas lire tes secrets, il
faut un déverrouillage par phrase de passe saisie à chaque démarrage - et donc
renoncer au redémarrage automatique.

## Construire

```
go build -o synsec ./cmd/synsec
```

Aucune dépendance C, donc la compilation croisée fonctionne sans outillage
particulier :

```
GOOS=linux GOARCH=arm64 go build -o synsec ./cmd/synsec
```

Sous Windows, `rebuild.cmd` enchaîne les tests, les binaires locaux et toutes
les cibles - Linux, macOS, Synology, Raspberry Pi.

## Licence

Copyright © 2026 Cyril Pineiro - SYNACKSYS

**GNU AGPL-3.0**, voir [LICENSE](LICENSE).

Utilise-le, modifie-le, redistribue-le librement. La seule contrepartie : qui
propose SYNSEC, modifié, comme service accessible par le réseau doit publier
ses modifications sous la même licence. Un particulier qui l'installe chez lui
n'a rien à faire.

L'interface expose la mention légale et l'adresse du code sur `/source`, comme
la licence le demande. Renseigne-la à la compilation :

```
go build -ldflags "-X synsec/internal/web.SourceURL=https://exemple/synsec" ./cmd/synsec
```

Les quatre bibliothèques utilisées sont sous licence BSD à trois clauses, qui
demande que leur avis de copyright accompagne toute distribution, binaires
compris. Il est reproduit dans
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), à livrer avec les
exécutables.
