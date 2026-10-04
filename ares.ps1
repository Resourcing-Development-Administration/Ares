#!/usr/bin/env pwsh
# Punto de entrada único de Ares en Windows (PowerShell) -- equivalente exacto de
# ares.sh: prepara el entorno (venv + dependencias) la primera vez y en cada cambio
# real de pyproject.toml/requirements.txt, y delega todo lo demás a la CLI real.
#
# Uso: .\ares.ps1 <subcomando> [flags...]   (mismos subcomandos que ares.sh / python cli\main.py)
#   .\ares.ps1 list-tests
#   .\ares.ps1 discover
#   .\ares.ps1 update-rules
#   .\ares.ps1 scan --command python --args target_server.py --out reporte.html
#   .\ares.ps1 vet  --transport http --url https://mi-server.com/mcp
#   .\ares.ps1 serve
#
# Si PowerShell bloquea el script por la política de ejecución (ExecutionPolicy),
# corré una sola vez (como usuario, no hace falta admin):
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# o invocá este archivo puntual sin cambiar la política global:
#   powershell -ExecutionPolicy Bypass -File .\ares.ps1 <subcomando> ...
#
# IMPORTANTE -- aislamiento de proceso (engine/core/sandbox.py): `prlimit` y `bwrap`
# son utilidades de Linux (util-linux / bubblewrap) sin equivalente en Windows. En
# Windows, el subprocess stdio del target corre SIN el RLIMIT de memoria/CPU/procesos/
# FDs ni los namespaces de PID/IPC/red que sí aplican en Linux -- Ares lo detecta y lo
# avisa como error informativo en cada scan (no es un fallo silencioso), pero la
# mitigación real de esa clase de ataque hoy es Linux-only. Ver sección "Resiliencia
# del motor" del README.
#
# Ver MANUAL.md para la referencia completa de flags.

$ErrorActionPreference = "Stop"

# --- resolver el directorio real de Ares (funciona aunque se invoque con ruta relativa) ---
$AresDir = $PSScriptRoot
$VenvDir = Join-Path $AresDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$DepsHashFile = Join-Path $VenvDir ".ares_deps_hash"

function Log($msg) { Write-Host "[ares.ps1] $msg" -ForegroundColor DarkGray }

# --- Python 3.11+ -- preferí el launcher oficial `py` (instala junto con python.org),
# con fallback a `python` a secas (algunos entornos -- venvs anidados, MSYS2 -- no
# tienen `py`). $env:ARES_PYTHON pisa todo esto si está seteado. ---
$PythonBin = $env:ARES_PYTHON
if (-not $PythonBin) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $PythonBin = "py"
        $PythonArgsPrefix = @("-3")
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $PythonBin = "python"
        $PythonArgsPrefix = @()
    } else {
        Log "No se encontro 'py' ni 'python' en PATH. Instala Python 3.11+ desde python.org (tildando 'Add to PATH') o seteá `$env:ARES_PYTHON a la ruta completa de python.exe."
        exit 1
    }
} else {
    $PythonArgsPrefix = @()
}

$PyOk = & $PythonBin @PythonArgsPrefix -c "import sys; print(1 if sys.version_info >= (3, 11) else 0)"
if ($PyOk -ne "1") {
    $PyVer = & $PythonBin @PythonArgsPrefix -c "import sys; print(sys.version)"
    Log "Ares necesita Python 3.11+; se encontro '$PyVer'. Seteá `$env:ARES_PYTHON a la ruta de un python.exe 3.11+."
    exit 1
}

# --- crear el venv si no existe ---
if (-not (Test-Path $VenvPython)) {
    Log "No se encontro .venv -- creando entorno virtual en $VenvDir ..."
    & $PythonBin @PythonArgsPrefix -m venv $VenvDir
}

# --- (re)instalar dependencias solo si pyproject.toml/requirements.txt cambiaron ---
# (hash de cada archivo por separado y concatenado -- no necesita coincidir bit a bit
# con el sha256sum de ares.sh, solo cambiar cuando cambian esos archivos)
$ProjectToml = Join-Path $AresDir "pyproject.toml"
$Requirements = Join-Path $AresDir "requirements.txt"
$CurrentHash = ""
foreach ($f in @($ProjectToml, $Requirements)) {
    if (Test-Path $f) {
        $CurrentHash += (Get-FileHash -Path $f -Algorithm SHA256).Hash
    }
}
$PreviousHash = if (Test-Path $DepsHashFile) { Get-Content $DepsHashFile -Raw } else { "" }

if ($CurrentHash -ne $PreviousHash) {
    Log "Instalando/actualizando dependencias (pip install -e .)..."
    & $VenvPython -m pip install -q --upgrade pip
    & $VenvPython -m pip install -q -e $AresDir
    Set-Content -Path $DepsHashFile -Value $CurrentHash -NoNewline
}

& $VenvPython (Join-Path $AresDir "cli\main.py") @args
exit $LASTEXITCODE
