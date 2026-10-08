#!/usr/bin/env python3
"""Opt-in HTTPS incident notification dispatcher; preview by default.

Uses only the local health issue codes/timestamp, never file contents or
research records. Does not send without an explicit --send AND a private
operator-provided HTTPS webhook URL file. No default timer is enabled.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib import request
from urllib.parse import urlsplit

HEALTH = Path("/var/lib/slipcage-health/status.json")
STATE = Path("/var/lib/slipcage-alerts")
DESTINATION_FILE = Path("/etc/slipcage/health-webhook.url")
MAX_HEALTH_AGE_SECONDS = 3 * 3600
MAX_BYTES = 32 * 1024
MAX_ISSUES = 32
ISSUE_CODE = re.compile(r"^[a-zA-Z0-9_:.@/-]{1,128}$")
MAX_RESPONSE = 512


def safe_json(path: Path, *, maximum: int = MAX_BYTES) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError("Unsafe status file")
    with path.open("r", encoding="utf-8") as file:
        doc = json.load(file)
    if not isinstance(doc, dict):
        raise ValueError("Invalid status record")
    return doc


def validate_health(snapshot: dict, *, now: datetime) -> tuple[list[str], str]:
    when = datetime.fromisoformat(snapshot["checked_utc"])
    if when.tzinfo is None:
        raise ValueError("Naive health check timestamp")
    age = (now - when).total_seconds()
    if age < -120 or age > MAX_HEALTH_AGE_SECONDS:
        raise ValueError("Health snapshot too old or from the future")
    issues = snapshot.get("issues")
    if (not isinstance(issues, list) or len(issues) > MAX_ISSUES or
            any(not isinstance(i, str) or not ISSUE_CODE.fullmatch(i) for i in issues)):
        raise ValueError("Invalid health issue codes")
    if snapshot.get("healthy") is not (len(issues) == 0):
        raise ValueError("Inconsistent health snapshot")
    return sorted(set(issues)), when.isoformat()


def endpoint_url(path: Path) -> str:
    stat_info = path.lstat()
    if not stat.S_ISREG(stat_info.st_mode) or stat_info.st_size > 2048:
        raise ValueError("Webhook config is unsafe")
    if stat_info.st_mode & 0o077:
        raise ValueError("Webhook config must be private (mode 0600)")
    url = path.read_text(encoding="utf-8").strip()
    parts = urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or
            parts.username or parts.password or parts.fragment or
            parts.port not in (None, 443) or
            parts.hostname.lower() in ("localhost",) or
            not re.fullmatch(r"[a-zA-Z0-9.-]+", parts.hostname) or
            "." not in parts.hostname):
        raise ValueError("HTTPS webhook hostname/port invalid")
    return url


def send_webhook(url: str, payload: dict) -> None:
    # Do not permit redirects (prevents reposting issue data to a new domain).
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    client = request.build_opener(NoRedirect)
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    req = request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "Slipcage-health/0.10"
    }, method="POST")
    with client.open(req, timeout=8) as result:
        if not 200 <= result.status < 300:
            raise OSError("Notification delivery rejected")
        result.read(MAX_RESPONSE)


def persist(destination: Path, payload: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=".delivered-", dir=destination.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(payload, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)


def dispatch(*, health: Path = HEALTH, state: Path = STATE,
             destination: Path = DESTINATION_FILE, send: bool = False,
             now: datetime | None = None, sender=send_webhook) -> dict:
    now = now or datetime.now(timezone.utc)
    snapshot = safe_json(health)
    issues, checked = validate_health(snapshot, now=now)
    fingerprint = hashlib.sha256(json.dumps(issues, sort_keys=True).encode()).hexdigest()
    payload = {
        "service": "slipcage", "type": "warning" if issues else "recovered",
        "issues": issues, "health_checked_utc": checked,
    }
    if not send:
        # Dry-run needs neither a webhook config nor an alert state directory.
        return {"mode": "preview", "will_notify": bool(issues),
                "event": payload, "delivered": False}
    if state.is_symlink() or not state.is_dir():
        raise ValueError("Private alert state directory missing")
    url = endpoint_url(destination)
    lock = state / ".notify.lock"
    if lock.is_symlink():
        raise ValueError("Symlinked notification lock")
    with lock.open("a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = state / "last-delivered.json"
        record = {}
        if previous.exists():
            record = safe_json(previous)
        last = record.get("issue_signature")
        # Never transmit an initial healthy state or repeat a delivered state.
        if (last is None and not issues) or last == fingerprint:
            return {"mode": "send", "delivered": False, "reason": "no_new_transition",
                    "event": payload}
        # Delivery result is persisted only after a successful 2xx response.
        sender(url, payload)
        persist(previous, {"issue_signature": fingerprint,
                           "delivered_utc": now.isoformat(),
                           "last_issues": issues})
        return {"mode": "send", "delivered": True, "event": payload}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send", action="store_true",
                        help="EXPLICIT opt-in HTTPS transmission, requires private webhook config.")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        result = dispatch(send=args.send)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("SLIPCAGE_ALERT_ERROR " + type(exc).__name__, file=sys.stderr)
        return 2
    # Never print a webhook URL or token in logs.
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
