# Licences tierces

SYNSEC est distribué sous licence AGPL-3.0 (voir `LICENSE`). Il incorpore les
bibliothèques ci-dessous, chacune sous licence BSD à trois clauses, qui exige
que leur avis de copyright accompagne toute distribution - y compris celle
d'un binaire compilé.

La BSD à trois clauses est permissive : elle se combine sans difficulté avec
l'AGPL, qui ne s'applique qu'au code de SYNSEC lui-même.

Ce fichier doit donc voyager avec les exécutables : à côté de `synsec.exe`,
dans l'archive livrée, ou dans l'image de conteneur.

| Bibliothèque | Version | Licence | Usage dans SYNSEC |
|---|---|---|---|
| `golang.org/x/crypto` | v0.31.0 | BSD-3-Clause | Argon2id, XChaCha20-Poly1305 |
| `golang.org/x/sys` | v0.46.0 | BSD-3-Clause | service Windows, DPAPI |
| `golang.org/x/term` | v0.27.0 | BSD-3-Clause | saisie de mot de passe sans écho |
| `modernc.org/sqlite` | v1.54.0 | BSD-3-Clause | base de données, en Go pur |

> Les versions ci-dessus reflètent `go.mod`. Après un `go mod tidy` qui les
> fait bouger, mets ce tableau à jour.

## golang.org/x/crypto, golang.org/x/sys, golang.org/x/term

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## modernc.org/sqlite

```
Copyright (c) 2017 The Sqlite Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## SQLite lui-même

`modernc.org/sqlite` est une transposition en Go du code source de SQLite, qui
est dans le **domaine public**. Ses auteurs n'imposent aucune condition :

> The author disclaims copyright to this source code. In place of a legal
> notice, here is a blessing: May you do good and not evil.

## Vérifier

Les textes ci-dessus sont ceux publiés par les projets concernés. Pour les
confronter aux fichiers réellement présents dans les versions que tu compiles :

```
go install github.com/google/go-licenses@latest
go-licenses report ./... > licences.txt
```

Ou plus simplement, les fichiers `LICENSE` dans le cache des modules :

```
type %GOPATH%\pkg\mod\golang.org\x\crypto@v0.31.0\LICENSE
```
