@echo off
rem Forwarder delgado a ares.ps1 para quien prefiera cmd.exe o doble-click en vez de
rem powershell -- -ExecutionPolicy Bypass acá es SOLO para esta invocación puntual,
rem no toca la politica de ejecucion global del usuario.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ares.ps1" %*
