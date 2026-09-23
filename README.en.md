*[Français](README.md) · **English***

# SYNSEC

A secrets server for your home. One binary, no database to install, no runtime
to keep alive: your passwords and keys stay in your house, encrypted, and your
devices come and fetch them on their own.

Built for someone running home automation - Home Assistant, Zigbee, MQTT,
backup scripts - rather than for a company.

## What it does

- **One vault per purpose.** "Maison", "Sauvegardes", "Bureau". Each vault has
  its own encryption key.
- **A secret is an entry** with a readable label and a technical identifier.
  You write "Mot de passe MQTT", your devices ask for `mot_de_passe_mqtt`.
- **Bring what you already have**: pick your Home Assistant `secrets.yaml` or
  your `.env` in the interface, or run `synsec import Maison secrets.yaml`.
- **A web interface and a command line that are equals**: same vaults, same
  secrets, same rules. A token-based **REST API** for devices.
- **Everyone sees only what is theirs** or what was shared with them, the
  server administrator included.
- **Second factor, your choice**: a six-digit code or a FIDO2 key - YubiKey,
  SoloKey, Windows Hello, Touch ID. Both if you want.
- **The master key is sealed in the machine's TPM** when there is one, on
  Windows as on Linux: it never comes out, so it is not on the disk. Without a
  chip, SYNSEC takes the fallback the system offers and says which one, before
  installing anything.
- **Everything is written down**, reads as well as writes. A secret's page
  shows who opened it, refusals included.
- **Told when something is out of the ordinary**: a device refused, a vault
  deleted, an access granted. SYNSEC posts a signed message to an address you
  choose - Home Assistant, ntfy, Gotify, a Discord channel. No third party, no
  quota.
- **Starts on its own** as a Windows service or a systemd unit, with nobody
  typing anything after a power cut.

## Quick start

```
synsec init
synsec cert trust
synsec utilisateur create cyril
synsec service install
```

Then open `https://<your-machine-name>:8787/`.

The four commands are detailed in [the installation guide](docs/installation.md),
in French.

## Documentation

The manuals are in French. This page is the summary.

| Document | For |
|---|---|
| [Installation](docs/installation.md) | Putting SYNSEC on a machine and making it start by itself |
| [Utilisation](docs/utilisation.md) | Storing secrets, sharing them, connecting a device |
| [Administration](docs/administration.md) | Accounts, backup, recovery, alerts, key rotation |
| [The agent](docs/agent.md) | Injecting secrets into a program, on Windows, Linux and macOS |

## What the security covers, and what it does not

Read this before trusting it with anything that matters.

**Covered.** Values are encrypted with XChaCha20-Poly1305 under a per-vault
key, itself sealed by a root key the operating system protects. A lost backup
or a database dump is unusable: what opens the key is not inside it. Every read
and every write leaves a named trace in the audit log.

**Whole-disk theft** needs a distinction, and what settles it is the chip, not
the operating system. With a TPM, on Windows as on Linux, the key is sealed
inside it and never comes out: the disk alone is worthless. Without one, what
opens the key sits on that same disk - DPAPI on Windows, a file reserved to
the service on Linux - and only volume encryption, BitLocker or LUKS, makes up
for it. The commands are in
[the installation guide](docs/installation.md#7-chiffrer-le-disque): on a
machine without a chip, it is a step to take, not an option.

**Not covered.** The root key is unsealed automatically at boot - that is what
lets your home automation box come back at three in the morning with nobody
there. An operating system administrator can therefore obtain the same key and
read the database. The separation between accounts is a rule SYNSEC enforces,
not a cryptographic barrier.

If you need a system administrator to be unable to read your secrets, you need
a passphrase typed at every boot, and therefore no unattended restart.

**In short: SYNSEC is exactly as secure as the machine hosting it.** There is
no magic. Encryption moves the problem to the key, and the key is guarded by
the operating system. A TPM, an encrypted volume and a dedicated service
account are not comfort: they are the floor everything else stands on.

## Building

```
go build -o synsec ./cmd/synsec
```

No C dependency, so cross-compiling needs no toolchain:

```
GOOS=linux GOARCH=arm64 go build -o synsec ./cmd/synsec
```

On Windows, `rebuild.cmd` chains the tests, the local binaries and every
target - Linux, macOS, Synology, Raspberry Pi.

## Licence

Copyright © 2026 Cyril Pineiro - [SYNACKSYS](https://synacksys.fr/open-source/)

**GNU AGPL-3.0**, see [LICENSE](LICENSE).

Use it, modify it, redistribute it freely. The one condition: whoever offers
SYNSEC, modified, as a service reachable over a network must publish their
modifications under the same licence. Someone installing it at home owes
nothing.

The interface shows the legal notice and the address of the source on
`/source`, as the licence requires. Set it at build time:

```
go build -ldflags "-X synsec/internal/web.SourceURL=https://git.example.com/me/synsec" ./cmd/synsec
```

The four libraries used are under the three-clause BSD licence, which requires
their copyright notice to travel with any distribution, binaries included. It
is reproduced in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), to ship
alongside the executables.
