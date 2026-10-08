"""SQLite-backed, attempt-fenced delivery of metadata-only advisory reviews.

Dagu is a delivery mechanism, not the source of truth for research state.
A timer retries abandoned work. Obsolete Dagu deliveries are inert because
the worker must atomically claim its exact opaque attempt token.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import re
import secrets
import sqlite3
import subprocess
import sys

SCHEMA = """
CREATE TABLE IF NOT EXISTS review_attempts (
 candidate_id TEXT PRIMARY KEY,
 token TEXT NOT NULL,
 state TEXT NOT NULL,
 created_at TEXT NOT NULL,
 started_at TEXT,
 boot_id TEXT,
 worker_pid INTEGER,
 worker_start_ticks TEXT,
 attempts INTEGER NOT NULL DEFAULT 1
);
"""
TOKEN = re.compile(r"^[a-f0-9]{32}$")
QUEUED_STALE = timedelta(minutes=30)
RUNNING_GRACE = timedelta(minutes=2)
MAX_ATTEMPTS = 3


def stamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


def elapsed(value: str | None, now: datetime) -> timedelta | None:
    try:
        start = datetime.fromisoformat(value)
        if start.tzinfo is None:
            return None
        return now.astimezone(timezone.utc) - start.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def boot_id() -> str | None:
    try:
        return open("/proc/sys/kernel/random/boot_id", encoding="ascii").read().strip()
    except OSError:
        return None


def process_start(pid: int) -> str | None:
    """Linux /proc PID+start tick prevents PID-reuse false positives."""
    try:
        raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
        fields = raw.rsplit(") ", 1)[1].split()
        # Field 22 (starttime), where the fields following comm begin at #3.
        return fields[19]
    except (OSError, IndexError, ValueError):
        return None


def worker_alive(pid: int | None, start: str | None,
                 recorded_boot: str | None) -> bool | None:
    """True=active, False=provably gone, None=cannot safely determine."""
    current_boot = boot_id()
    if not current_boot or not recorded_boot or not pid or not start:
        return None
    if current_boot != recorded_boot:
        return False
    current_start = process_start(pid)
    if current_start is None:
        # Distinguish non-existent PID from a procfs access failure.
        return False if not os.path.exists(f"/proc/{pid}") else None
    return current_start == start


def claim_next(conn: sqlite3.Connection, limit: int, now: datetime | None = None):
    """Claim one new attempt with an atomic global outstanding-cap check."""
    if not 1 <= limit <= 100:
        raise ValueError("Outstanding limit must be between 1 and 100")
    now = now or datetime.now(timezone.utc)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        outstanding = conn.execute(
            "SELECT COUNT(*) FROM candidates WHERE status IN ('queued','running')"
        ).fetchone()[0]
        if outstanding >= limit:
            return None
        # Skip candidates that exhausted retries, without blocking other work.
        for row in conn.execute("""SELECT c.id, COALESCE(a.attempts,0) AS attempts
                FROM candidates c LEFT JOIN review_attempts a ON a.candidate_id=c.id
                WHERE c.status='pending'
                ORDER BY c.score DESC, c.discovered_at, c.id""").fetchall():
            if row["attempts"] >= MAX_ATTEMPTS:
                conn.execute(
                    "UPDATE candidates SET status='needs_attention' WHERE id=? AND status='pending'",
                    (row["id"],))
                continue
            token = secrets.token_hex(16)
            conn.execute(
                "UPDATE candidates SET status='queued',queued_at=? WHERE id=? AND status='pending'",
                (stamp(now), row["id"]))
            conn.execute("""INSERT INTO review_attempts(
                candidate_id,token,state,created_at,started_at,boot_id,
                worker_pid,worker_start_ticks,attempts)
                VALUES(?,?,'queued',?,NULL,NULL,NULL,NULL,?)
                ON CONFLICT(candidate_id) DO UPDATE SET
                    token=excluded.token,state='queued',created_at=excluded.created_at,
                    started_at=NULL,boot_id=NULL,worker_pid=NULL,worker_start_ticks=NULL,
                    attempts=excluded.attempts
                """, (row["id"], token, stamp(now), row["attempts"] + 1))
            return row["id"], token
    return None


def rollback_delivery(conn, candidate_id: str, token: str) -> None:
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT state,token FROM review_attempts WHERE candidate_id=?",
            (candidate_id,)).fetchone()
        if current and current["state"] == "queued" and current["token"] == token:
            conn.execute("UPDATE candidates SET status='pending',queued_at=NULL "
                         "WHERE id=? AND status='queued'", (candidate_id,))
            conn.execute("UPDATE review_attempts SET state='delivery_failed' "
                         "WHERE candidate_id=? AND token=?", (candidate_id, token))


def enqueue(conn: sqlite3.Connection, workflow: str, limit: int,
            *, runner=subprocess.run, now: datetime | None = None) -> dict:
    submitted = 0
    failed = 0
    while True:
        claim = claim_next(conn, limit, now)
        if not claim:
            break
        candidate_id, token = claim
        try:
            runner(["/usr/local/bin/dagu", "enqueue", workflow, "--",
                    f"candidate_id={candidate_id}", f"attempt={token}"],
                   check=True, timeout=20, capture_output=True, text=True)
            submitted += 1
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            rollback_delivery(conn, candidate_id, token)
            failed += 1
            print(f"WARNING: delivery of {candidate_id[:12]} failed: {exc}", file=sys.stderr)
            # Avoid rapidly retrying a broken CLI or Dagu outage in the same run.
            break
    return {"enqueued": submitted, "delivery_failures": failed}


def start(conn: sqlite3.Connection, candidate_id: str, token: str,
          now: datetime | None = None) -> bool:
    if not TOKEN.fullmatch(token):
        raise ValueError("Attempt must be 32 lowercase hex characters")
    pid = os.getpid()
    boot = boot_id()
    tick = process_start(pid)
    if not boot or not tick:
        raise OSError("Cannot establish Linux process identity for fenced review")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute("""UPDATE candidates SET status='running'
            WHERE id=? AND status='queued'
              AND EXISTS (SELECT 1 FROM review_attempts
                WHERE candidate_id=? AND token=? AND state='queued')""",
            (candidate_id, candidate_id, token)).rowcount
        if changed:
            conn.execute("""UPDATE review_attempts SET state='running',
                started_at=?,boot_id=?,worker_pid=?,worker_start_ticks=?
                WHERE candidate_id=? AND token=?""",
                (stamp(now), boot, pid, tick, candidate_id, token))
    return changed == 1


def finish(conn: sqlite3.Connection, candidate_id: str, token: str,
           now: datetime | None = None) -> bool:
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        changed = conn.execute("""UPDATE candidates SET status='reviewed',reviewed_at=?
            WHERE id=? AND status='running'
              AND EXISTS (SELECT 1 FROM review_attempts
                WHERE candidate_id=? AND token=? AND state='running')""",
            (stamp(now), candidate_id, candidate_id, token)).rowcount
        if changed:
            conn.execute("""UPDATE review_attempts SET state='finished'
                WHERE candidate_id=? AND token=? AND state='running'""",
                (candidate_id, token))
        return changed == 1


def reconcile(conn: sqlite3.Connection, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    reclaimed_queued, reclaimed_running, held, legacy = 0, 0, 0, 0
    # Single SQLite writer transaction serializes reconciliation and starts.
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("""SELECT c.id,c.status,a.token,a.created_at,a.started_at,
                  a.boot_id,a.worker_pid,a.worker_start_ticks,a.state
               FROM candidates c LEFT JOIN review_attempts a ON c.id=a.candidate_id
               WHERE c.status IN ('queued','running')""").fetchall()
        for row in rows:
            if not row["token"]:
                # Never gamble with pre-v0.3 queued Dagu work.
                legacy += 1
                continue
            if row["status"] == "queued" and row["state"] == "queued":
                age = elapsed(row["created_at"], now)
                if age is not None and age >= QUEUED_STALE:
                    conn.execute("UPDATE candidates SET status='pending',queued_at=NULL "
                                 "WHERE id=? AND status='queued'", (row["id"],))
                    conn.execute("UPDATE review_attempts SET state='expired' "
                                 "WHERE candidate_id=? AND token=?", (row["id"],row["token"]))
                    reclaimed_queued += 1
            elif row["status"] == "running" and row["state"] == "running":
                age = elapsed(row["started_at"], now)
                alive = worker_alive(row["worker_pid"], row["worker_start_ticks"], row["boot_id"])
                if age is not None and age >= RUNNING_GRACE and alive is False:
                    conn.execute("UPDATE candidates SET status='pending',queued_at=NULL "
                                 "WHERE id=? AND status='running'", (row["id"],))
                    conn.execute("UPDATE review_attempts SET state='expired' "
                                 "WHERE candidate_id=? AND token=?", (row["id"],row["token"]))
                    reclaimed_running += 1
                elif alive is None:
                    held += 1
    return {"queued_reclaimed": reclaimed_queued, "running_reclaimed": reclaimed_running,
            "ambiguous_running": held, "legacy_untracked": legacy}
