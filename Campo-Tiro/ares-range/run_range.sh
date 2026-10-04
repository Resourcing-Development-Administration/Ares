#!/usr/bin/env bash
# Corre Ares contra todo el "rango de práctica" (targets vulnerables propios +
# el server hostil-al-escáner) y deja un reporte HTML/JSON/SARIF por target en
# reports/, pensado como paquete de remediación inmediata.
#
# Uso: ./run_range.sh   (desde cualquier directorio)
set -uo pipefail

HERE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ARES_DIR="$(cd -P "$HERE/../.." >/dev/null 2>&1 && pwd)"
OUT="$HERE/reports"
mkdir -p "$OUT"

cd "$ARES_DIR"

echo "=== 1/4: target_server.py (stdio, vulnerable de práctica original) ==="
./ares.sh scan --command python3 --args "target_server.py" \
  --out "$OUT/01_target_server.html" --sarif-out "$OUT/01_target_server.sarif" \
  --print 2>&1 | tee "$OUT/01_target_server.log"

echo
echo "=== 2/4: target_server_http.py (http, sin auth) ==="
python3 target_server_http.py &
HTTP_PID=$!
sleep 2
./ares.sh scan --transport http --url http://127.0.0.1:8765/mcp \
  --out "$OUT/02_target_server_http.html" --sarif-out "$OUT/02_target_server_http.sarif" \
  --print 2>&1 | tee "$OUT/02_target_server_http.log"
kill "$HTTP_PID" 2>/dev/null
wait "$HTTP_PID" 2>/dev/null

echo
echo "=== 3/4: acme-internal-tools (stdio, flagship -- SAST + OSV.dev + typosquat) ==="
# defaults + los dos tests de supplychain opt-in (dependency_vulnerabilities, source_sast) --
# necesitan --source-path/--allow-network explícitos, no corren con default_enabled.
ALL_TESTS="adv.confused_deputy,adv.destructive_no_confirmation,adv.injection_passthrough,adv.rug_pull,\
auth.oauth_metadata_security,auth.unauthenticated_access,dynamic.command_injection_confirmed,\
dynamic.credential_harvest_paths,dynamic.fuzz_resources,dynamic.fuzz_tools,\
dynamic.path_traversal_confirmed,exposure.cors_misconfig,exposure.network_reachability,\
exposure.session_id_entropy,exposure.transport_security,recon.audit_logging,recon.enumerate,\
recon.excessive_permissions,recon.suspicious_descriptions,static.known_cve_check,static.no_schema,\
static.schema_permissive,supplychain.dependency_vulnerabilities,supplychain.exfiltration_chain,\
supplychain.malicious_patterns,supplychain.secret_exposure,supplychain.source_sast,supplychain.tool_squatting"
./ares.sh scan --command python3 --args "$HERE/enterprise_source/server.py" \
  --source-path "$HERE/enterprise_source" \
  --package-name mcp-server-fetchh \
  --allow-network \
  --tests "$ALL_TESTS" \
  --out "$OUT/03_acme_internal_tools.html" --sarif-out "$OUT/03_acme_internal_tools.sarif" \
  --print 2>&1 | tee "$OUT/03_acme.log"

echo
echo "=== 4/4: hostile-to-ares (stdio, resiliencia del propio motor) ==="
./ares.sh scan --command python3 --args "$HERE/hostile_to_scanner.py" \
  --out "$OUT/04_hostile_to_scanner.html" --sarif-out "$OUT/04_hostile_to_scanner.sarif" \
  --print 2>&1 | tee "$OUT/04_hostile.log"

echo
echo "Reportes en: $OUT"
