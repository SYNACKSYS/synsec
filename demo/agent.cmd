@echo off
cls
rem Le programme lance ne sait rien de SYNSEC : il lit une variable.
rem C'est l'agent qui va chercher la valeur et la lui remet en memoire.

set /p SYNSEC_TOKEN=<"%~dp0jeton.txt"
set SYNSEC_ADDR=https://synsec.synacksys.fr

"%~dp0..\dist\synsec-agent-windows-amd64.exe" run -secret router_admin -- cmd /c "echo. & echo   ROUTER_ADMIN = %%ROUTER_ADMIN%% & echo."
