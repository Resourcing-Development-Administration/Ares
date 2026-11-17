#!/usr/bin/env bash
# setup.sh — Provision the php2shell lab environment.
#
# Sets up a vulnerable PHP environment in a local container/VM for safe testing
# of LFI→RCE via session.upload_progress (CVE-2026-109618/109619).
#
# Requirements:
#   - Docker or Podman available
#   - Authorized lab VM (this script must ONLY run in the lab environment)
#   - Internet access to pull the base image (or offline: adjust BASE_IMAGE)
#
# Usage: bash setup.sh [--port 8081] [--php 8.1] [--stop] [--status]

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

PORT="${LAB_PORT:-8081}"
PHP_VER="${LAB_PHP:-8.1}"
CONTAINER_NAME="ares-php2shell-lab"
BASE_IMAGE="php:${PHP_VER}-apache"
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
WEBROOT="$LAB_DIR/www"
LOG_FILE="$LAB_DIR/lab.log"

# ── Helpers ───────────────────────────────────────────────────────────────────

log() { echo "[setup.sh] $*" | tee -a "$LOG_FILE"; }
die() { echo "[setup.sh] ERROR: $*" >&2; exit 1; }

docker_cmd() {
    if command -v podman &>/dev/null; then
        podman "$@"
    elif command -v docker &>/dev/null; then
        docker "$@"
    else
        die "Neither docker nor podman found — install one first"
    fi
}

# ── Argument parsing ──────────────────────────────────────────────────────────

ACTION="start"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)   PORT="$2"; shift 2 ;;
        --php)    PHP_VER="$2"; BASE_IMAGE="php:${PHP_VER}-apache"; shift 2 ;;
        --stop)   ACTION="stop"; shift ;;
        --status) ACTION="status"; shift ;;
        --clean)  ACTION="clean"; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Stop action ───────────────────────────────────────────────────────────────

if [[ "$ACTION" == "stop" ]]; then
    log "Stopping lab container $CONTAINER_NAME"
    docker_cmd stop "$CONTAINER_NAME" 2>/dev/null || true
    docker_cmd rm   "$CONTAINER_NAME" 2>/dev/null || true
    log "Lab stopped"
    exit 0
fi

# ── Status action ─────────────────────────────────────────────────────────────

if [[ "$ACTION" == "status" ]]; then
    if docker_cmd ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        log "Lab running on port $PORT — http://localhost:$PORT"
    else
        log "Lab not running"
    fi
    exit 0
fi

# ── Clean action ──────────────────────────────────────────────────────────────

if [[ "$ACTION" == "clean" ]]; then
    docker_cmd stop  "$CONTAINER_NAME" 2>/dev/null || true
    docker_cmd rm    "$CONTAINER_NAME" 2>/dev/null || true
    docker_cmd rmi   "$BASE_IMAGE"     2>/dev/null || true
    rm -rf "$WEBROOT"
    log "Lab cleaned"
    exit 0
fi

# ── Start action ──────────────────────────────────────────────────────────────

log "Setting up php2shell lab (PHP $PHP_VER, port $PORT)"

# Create vulnerable web application
mkdir -p "$WEBROOT/uploads"

cat > "$WEBROOT/upload.php" << 'PHP'
<?php
// Vulnerable lab endpoint: accepts file uploads, stores in /uploads/
// session.upload_progress.enabled = On (default in PHP 5.4+)
// This is intentionally vulnerable for lab testing.

session_start();

$upload_dir = __DIR__ . '/uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $filename = basename($_FILES['file']['name']);
    $dest = $upload_dir . $filename;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo json_encode(['status' => 'ok', 'path' => '/uploads/' . $filename]);
    } else {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'msg' => 'Upload failed']);
    }
    exit;
}

// Serve upload form
header('Content-Type: text/html');
?>
<!DOCTYPE html>
<html>
<body>
<form method="post" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="probe">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
</body>
</html>
PHP

cat > "$WEBROOT/index.php" << 'PHP'
<?php
// Lab index — allows LFI via ?file= parameter for session injection testing
session_start();

$file = $_GET['file'] ?? '';

if ($file) {
    // Vulnerable: no path traversal protection (intentional for lab)
    @include($file);
} else {
    echo "Lab ready. Session ID: " . session_id();
}
PHP

cat > "$WEBROOT/.htaccess" << 'HTACCESS'
# Enable PHP execution for alternate extensions (intentionally vulnerable)
AddHandler application/x-httpd-php .php .php5 .php7 .phtml .pht
Options -Indexes
HTACCESS

# PHP config: enable session.upload_progress (default in PHP 5.4+)
cat > "$LAB_DIR/php.ini" << 'INI'
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.upload_progress.prefix = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
upload_max_filesize = 10M
post_max_size = 10M
display_errors = On
error_reporting = E_ALL
INI

# Stop existing container if running
docker_cmd stop "$CONTAINER_NAME" 2>/dev/null || true
docker_cmd rm   "$CONTAINER_NAME" 2>/dev/null || true

log "Starting container $CONTAINER_NAME on port $PORT"

docker_cmd run -d \
    --name "$CONTAINER_NAME" \
    -p "${PORT}:80" \
    -v "$WEBROOT:/var/www/html:z" \
    -v "$LAB_DIR/php.ini:/usr/local/etc/php/php.ini:z" \
    "$BASE_IMAGE"

# Wait for container
sleep 2

if docker_cmd ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
    log "Lab ready at http://localhost:$PORT"
    log "Upload endpoint: http://localhost:$PORT/upload.php"
    log "LFI endpoint:    http://localhost:$PORT/index.php?file=..."
    log "Session files:   /var/lib/php/sessions/ (inside container)"
    log ""
    log "To stop: bash setup.sh --stop"
    log "To test: python ../poc/verify_session_injection.py \\"
    log "           --target http://localhost:$PORT/upload.php \\"
    log "           --session-url http://localhost:$PORT/index.php"
else
    die "Container failed to start — check docker logs $CONTAINER_NAME"
fi
