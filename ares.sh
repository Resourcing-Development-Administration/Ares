#!/usr/bin/env bash
# Punto de entrada único de Ares. Prepara el entorno (venv + dependencias) la
# primera vez y en cada cambio real de pyproject.toml/requirements.txt, y
# delega todo lo demás a la CLI real -- no hace falta activar nada a mano.
#
# Uso: ./ares.sh <subcomando> [flags...]   (mismos subcomandos que 'python cli/main.py')
#   ./ares.sh list-tests
#   ./ares.sh discover
#   ./ares.sh update-rules
#   ./ares.sh scan --command python3 --args target_server.py --out reporte.html
#   ./ares.sh vet  --transport http --url https://mi-server.com/mcp
#   ./ares.sh serve
#
# Ver MANUAL.md para la referencia completa de flags.
set -euo pipefail

# --- resolver el directorio real de Ares, incluso si este script se invoca vía symlink ---
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
ARES_DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
VENV_DIR="$ARES_DIR/.venv"
DEPS_HASH_FILE="$VENV_DIR/.ares_deps_hash"

log() { echo "[ares.sh] $*" >&2; }

# --- Python 3.11+ (tomllib de la stdlib, usado por 'update-rules') ---
PYTHON_BIN="${ARES_PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  log "No se encontró '$PYTHON_BIN' en PATH. Instalá Python 3.11+ o seteá ARES_PYTHON=/ruta/a/python3."
  exit 1
fi
PY_OK=$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
if [ "$PY_OK" != "1" ]; then
  log "Ares necesita Python 3.11+; '$PYTHON_BIN' es $($PYTHON_BIN -V 2>&1). Seteá ARES_PYTHON=/ruta/a/python3.11+."
  exit 1
fi

# --- crear el venv si no existe ---
if [ ! -x "$VENV_DIR/bin/python" ]; then
  log "No se encontró .venv -- creando entorno virtual en $VENV_DIR ..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# --- (re)instalar dependencias solo si pyproject.toml/requirements.txt cambiaron ---
CURRENT_HASH="$(cat "$ARES_DIR/pyproject.toml" "$ARES_DIR/requirements.txt" 2>/dev/null | sha256sum | cut -d' ' -f1)"
PREVIOUS_HASH="$(cat "$DEPS_HASH_FILE" 2>/dev/null || echo "")"
if [ "$CURRENT_HASH" != "$PREVIOUS_HASH" ]; then
  log "Instalando/actualizando dependencias (pip install -e .)..."
  pip install -q --upgrade pip >&2
  pip install -q -e "$ARES_DIR" >&2
  echo "$CURRENT_HASH" > "$DEPS_HASH_FILE"
fi

exec python "$ARES_DIR/cli/main.py" "$@"
