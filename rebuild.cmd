@echo off
setlocal EnableDelayedExpansion

rem SYNSEC - compilation et tests.
rem
rem Machine de developpement : on compile, on ne fait pas tourner de serveur.
rem Aucun service n'est arrete ni relance, aucun secret ne vit ici, et rien
rem n'est produit a la racine : tout ce qui est compile atterrit dans dist\,
rem y compris la version Windows.
rem
rem CGO_ENABLED=0 partout : c'est ce qui rend la compilation croisee possible
rem sans chaine d'outils C, et ce qui donne un binaire sans dependance.

set "DIST=dist"
set "VERSION=v0.1.1"
set "CGO_ENABLED=0"

rem Ou trouver le code de cette version. La licence AGPL demande que quiconque
rem utilise le serveur puisse l'obtenir ; l'interface l'affiche sur /source.
rem Laisse vide tant que le code n'est publie nulle part.
set "SOURCE_URL=https://github.com/SYNACKSYS/synsec"

set "STAMP=-X synsec/internal/web.Version=%VERSION% -X synsec/internal/web.SourceURL=%SOURCE_URL%"

echo.
echo === Dependances ===
go mod tidy
if errorlevel 1 goto :fail

echo.
echo === Analyse statique ===
go vet ./...
if errorlevel 1 goto :fail

echo.
echo === Tests ===
go test ./...
if errorlevel 1 goto :fail

echo.
echo === Compilation croisee ===
if not exist "%DIST%" mkdir "%DIST%"

rem  cible            GOOS     GOARCH  GOARM
call :build linux-amd64    linux   amd64
call :build linux-arm64    linux   arm64
call :build linux-armv7    linux   arm     7
call :build macos-intel    darwin  amd64
call :build macos-apple    darwin  arm64
call :build windows-amd64  windows amd64
if defined BUILD_FAILED goto :fail

rem Les licences accompagnent les binaires, pas seulement les sources : la
rem BSD trois clauses des dependances l'exige explicitement pour toute
rem distribution sous forme binaire.
copy /Y LICENSE "%DIST%\LICENSE" >nul
copy /Y THIRD-PARTY-NOTICES.md "%DIST%\THIRD-PARTY-NOTICES.md" >nul

rem Empreintes, pour que celui qui telecharge puisse verifier qu'il a bien
rem recu ce qui a ete publie. Attendu de n'importe quel outil de securite.
rem
rem Le calcul se fait entierement avant l'ecriture : une redirection creerait
rem le fichier des le depart et Get-FileHash echouerait en le lisant vide.
echo.
echo === Empreintes ===
del /Q "%DIST%\SHA256SUMS" 2>nul
powershell -NoProfile -Command ^
  "$l = Get-ChildItem '%DIST%' -File | Get-FileHash -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLower() + '  ' + (Split-Path $_.Path -Leaf) }; [IO.File]::WriteAllLines((Join-Path (Resolve-Path '%DIST%') 'SHA256SUMS'), $l)"
if errorlevel 1 goto :fail
type "%DIST%\SHA256SUMS"

echo.
echo === Termine ===
echo   Synology Intel     : %DIST%\synsec-linux-amd64
echo   Synology ARM 64    : %DIST%\synsec-linux-arm64
echo   Synology ARM 32    : %DIST%\synsec-linux-armv7
echo   Raspberry Pi 3/4/5 : %DIST%\synsec-linux-arm64      (Raspberry Pi OS 64 bits)
echo   Raspberry Pi ancien: %DIST%\synsec-linux-armv7      (Raspberry Pi OS 32 bits)
echo.
echo   Sur la machine cible : uname -m
echo     x86_64   -^> amd64      aarch64  -^> arm64      armv7l -^> armv7
echo.
echo   Publier : mettre VERSION a la valeur du tag, recompiler, puis
echo             televerser le contenu de %DIST%\ dans la release GitHub.
echo.
endlocal
exit /b 0

rem build <suffixe> <GOOS> <GOARCH> [GOARM]
rem
rem Compile le serveur et l'agent pour une cible. L'agent seul suffit sur une
rem machine qui consomme des secrets ; le serveur n'y sert que si SYNSEC doit
rem y tourner.
:build
set "SUFFIX=%~1"
set "GOOS=%~2"
set "GOARCH=%~3"
set "GOARM=%~4"

set "EXT="
if "%GOOS%"=="windows" set "EXT=.exe"

echo   %SUFFIX%
go build -ldflags "-s -w %STAMP%" -o "%DIST%\synsec-%SUFFIX%%EXT%" ./cmd/synsec
if errorlevel 1 set "BUILD_FAILED=1"

go build -ldflags "-s -w -X main.agentVersion=%VERSION%" -o "%DIST%\synsec-agent-%SUFFIX%%EXT%" ./cmd/synsec-agent
if errorlevel 1 set "BUILD_FAILED=1"

set "GOOS="
set "GOARCH="
set "GOARM="
exit /b 0

:fail
echo.
echo *** ECHEC ***
endlocal
exit /b 1
