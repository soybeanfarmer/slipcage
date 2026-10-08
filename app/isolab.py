#!/usr/bin/env python3
"""Slipcage v0.1: metadata-only discovery/triage.

No PoC download, script execution, scanning, privileged containers, or exploitation.
External advisory text is data, never a shell command.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import intelligence

MATCHERS = {
    "hypervisor": re.compile(r"\b(qemu|kvm|virtualbox|hyper[- ]v)\b", re.I),
    "container": re.compile(r"\b(runc|containerd|moby|docker engine|docker daemon)\b", re.I),
}
ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
USER_AGENT = "slipcage-metadata-research/0.1 (independent research; no PoC execution)"
SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
 id TEXT PRIMARY KEY,
 source TEXT NOT NULL,
 source_id TEXT NOT NULL,
 cve TEXT,
 title TEXT NOT NULL,
 summary TEXT NOT NULL,
 reference_url TEXT NOT NULL,
 track TEXT NOT NULL,
 score INTEGER NOT NULL,
 published TEXT,
 updated TEXT,
 status TEXT NOT NULL DEFAULT 'pending',
 discovered_at TEXT NOT NULL,
 queued_at TEXT,
 reviewed_at TEXT,
 UNIQUE(source, source_id)
);
CREATE INDEX IF NOT EXISTS candidates_status_score ON candidates(status, score DESC);
""" + intelligence.SCHEMA


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db: str) -> sqlite3.Connection:
    path = Path(db)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.executescript(SCHEMA)
    return conn


def classify(title: str, summary: str) -> tuple[str, int] | None:
    # Match only known in-scope component names; descriptions are never executed.
    heading = title[:500]
    body = summary[:5000]
    scores = []
    for track, pattern in MATCHERS.items():
        if pattern.search(heading) or pattern.search(body):
            base = 55
            if pattern.search(heading):
                base += 25
            if re.search(r"\b(escape|out.of.bounds|use.after.free|memory corruption)\b", body, re.I):
                base += 10
            scores.append((track, min(base, 100)))
    return max(scores, key=lambda item: item[1]) if scores else None


def record(conn: sqlite3.Connection, item: dict) -> bool:
    track_score = classify(item["title"], item["summary"])
    if not track_score:
        return False
    track, score = track_score
    source = item["source"]
    source_id = item["source_id"]
    candidate_id = hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()
    conn.execute(
        """INSERT INTO candidates (
          id,source,source_id,cve,title,summary,reference_url,
          track,score,published,updated,discovered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source,source_id) DO UPDATE SET
          cve=excluded.cve,title=excluded.title,summary=excluded.summary,
          reference_url=excluded.reference_url,track=excluded.track,
          score=excluded.score,published=excluded.published,updated=excluded.updated
        """,
        (candidate_id, source, source_id, item.get("cve"), item["title"][:500],
         item["summary"][:8000], item["url"][:1000], track, score,
         item.get("published"), item.get("updated"), utc_now()),
    )
    refs = item.get("references") or []
    refs = [u for u in refs if isinstance(u, str) and len(u) <= 800][:30]
    conn.execute("""INSERT INTO candidate_evidence(candidate_id,references_json)
        VALUES (?, ?) ON CONFLICT(candidate_id) DO UPDATE SET
        references_json=excluded.references_json""", (candidate_id, json.dumps(refs)))
    return True


def fetch_json(url: str):
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(req, timeout=25) as response:
        if response.status != 200:
            raise ValueError(f"Unexpected HTTP status: {response.status}")
        # Maximum response ~8 MiB to avoid oversized feed memory/disk pressure.
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("Feed response exceeded 8 MiB limit")
    return json.loads(raw)


def github_items():
    url = "https://api.github.com/advisories?" + urlencode({
        "per_page": 100, "sort": "updated", "direction": "desc", "type": "reviewed"
    })
    data = fetch_json(url)
    if not isinstance(data, list):
        raise ValueError("GitHub advisory data was not a list")
    for obj in data:
        if not isinstance(obj, dict) or not obj.get("ghsa_id"):
            continue
        yield {
            "source": "github", "source_id": obj["ghsa_id"],
            "cve": obj.get("cve_id"),
            "title": obj.get("summary") or "(no title)",
            "summary": obj.get("description") or "",
            "url": obj.get("html_url") or "https://github.com/advisories",
            "published": obj.get("published_at"), "updated": obj.get("updated_at"),
            "references": [ref.get("url") if isinstance(ref, dict) else ref
                           for ref in (obj.get("references") or [])
                           if isinstance(ref, str) or
                           (isinstance(ref, dict) and isinstance(ref.get("url"), str))],
        }


def nvd_items():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=3)
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    params = {"lastModStartDate": iso(start), "lastModEndDate": iso(end),
              "resultsPerPage": 200, "startIndex": 0}
    # Bounded pagination; don't accidentally perform a bulk scrape.
    for page in range(3):
        params["startIndex"] = page * 200
        data = fetch_json(base + urlencode(params))
        entries = data.get("vulnerabilities", [])
        if not isinstance(entries, list):
            raise ValueError("NVD returned invalid vulnerabilities list")
        for entry in entries:
            cve = entry.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            english = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            yield {
                "source": "nvd", "source_id": cve_id, "cve": cve_id,
                "title": cve_id + ": " + english[:240], "summary": english,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                "published": cve.get("published"), "updated": cve.get("lastModified"),
                "references": [ref.get("url") for ref in (cve.get("references") or [])
                               if isinstance(ref, dict) and isinstance(ref.get("url"), str)],
            }
        if params["startIndex"] + len(entries) >= int(data.get("totalResults", 0)) or not entries:
            break


def sync(db: str) -> int:
    conn = connect(db)
    total = 0
    failures = 0
    for label, feed in (("github", github_items), ("nvd", nvd_items)):
        try:
            count = 0
            with conn:
                for item in feed():
                    if record(conn, item):
                        count += 1
            total += count
            print(f"{label}: matched={count}")
        except (HTTPError, URLError, TimeoutError, ValueError, OSError, KeyError, TypeError) as exc:
            failures += 1
            print(f"WARNING: {label} ingest failed ({type(exc).__name__}: {exc})", file=sys.stderr)
    print(f"matched_total={total} failed_sources={failures}")
    return 1 if failures == 2 else 0


def analyze(db: str) -> int:
    conn = connect(db)
    try:
        with conn:
            info = intelligence.analyze(conn)
        print(f"intelligence_candidates={info['candidates']} duplicate_pending={info['duplicates']}")
    finally:
        conn.close()
    return 0


def enqueue(db: str, workflow: str, max_outstanding: int) -> int:
    if not (1 <= max_outstanding <= 100):
        raise ValueError("max_outstanding must be between 1 and 100")
    conn = connect(db)
    queued = conn.execute("SELECT count(*) FROM candidates WHERE status='queued'").fetchone()[0]
    slots = max(0, max_outstanding - queued)
    jobs = conn.execute("SELECT id FROM candidates WHERE status='pending' ORDER BY score DESC, discovered_at LIMIT ?", (slots,)).fetchall()
    submitted = 0
    for job in jobs:
        candidate_id = job["id"]
        # No feed data or dynamic commands enter the subprocess: only a hashed ID.
        with conn:
            claimed = conn.execute("UPDATE candidates SET status='queued', queued_at=? WHERE id=? AND status='pending'", (utc_now(), candidate_id)).rowcount
        if not claimed:
            continue
        try:
            subprocess.run(["/usr/local/bin/dagu", "enqueue", workflow, "--", f"candidate_id={candidate_id}"],
                           check=True, timeout=20, capture_output=True, text=True)
            submitted += 1
        except (subprocess.CalledProcessError, TimeoutError, OSError) as exc:
            with conn:
                conn.execute("UPDATE candidates SET status='pending',queued_at=NULL WHERE id=? AND status='queued'", (candidate_id,))
            print(f"WARNING: enqueue failed for {candidate_id[:12]}: {exc}", file=sys.stderr)
    print(f"enqueued={submitted}, previously_outstanding={queued}")
    return 0


def report(db: str, output: str, candidate_id: str) -> int:
    if not ID_PATTERN.fullmatch(candidate_id):
        raise ValueError("Candidate IDs must be 64 lower-case SHA-256 hex characters")
    conn = connect(db)
    row = conn.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()
    if row is None:
        raise ValueError("Candidate not in database")
    out = Path(output)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = out / f"candidate-{stamp}-{candidate_id[:12]}.md"
    # Indent arbitrary remote title/summary as literal blockquote text, no HTML allowed.
    safe = lambda s: "\n".join("> " + html.escape(ln, quote=True) for ln in (s or "").splitlines()[:70])
    text = (
        "# Advisory triage (metadata-only)\n\n"
        f"- Candidate: `{candidate_id}`\n- Source: `{row['source']}`\n"
        f"- Track: `{row['track']}`\n- Priority score: `{row['score']}/100`\n"
        f"- CVE: `{row['cve'] or 'not supplied'}`\n"
        f"- Reference URL: {html.escape(row['reference_url'], quote=True)}\n"
        f"- Date reviewed: `{utc_now()}`\n\n" +
        intelligence.report_section(conn, candidate_id) +
        "## Published summary\n\n" + safe(row["title"]) + "\n\n"
        "## Published technical description\n\n" + safe(row["summary"][:6000]) + "\n\n"
        "## Next actions (human reviewed)\n\n"
        "- Confirm scope and affected versions in upstream source.\n"
        "- Read upstream patch/reproducer documentation; do not execute untrusted PoC code.\n"
        "- Identify an isolated test design and required provider authorization.\n"
        "- Distinguish a known advisory from a novel finding or a mere crash.\n\n"
        "**Status:** Advisory triage only. No vulnerability has been reproduced.\n"
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=out, delete=False) as f:
        tmp = Path(f.name)
        os.chmod(tmp, 0o600)
        f.write(text)
    os.replace(tmp, target)
    with conn:
        conn.execute("UPDATE candidates SET status='reviewed',reviewed_at=? WHERE id=?", (utc_now(), candidate_id))
    print(f"report={target}")
    return 0


def smoke(output: str) -> int:
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    outfile = path / "smoke-ok.json"
    outfile.write_text(json.dumps({"status": "ok", "timestamp": utc_now(), "mode": "metadata-only"}, indent=2) + "\n")
    os.chmod(outfile, 0o600)
    print(f"smoke=ok artifact={outfile}")
    return 0


def status(db: str) -> int:
    conn = connect(db)
    for r in conn.execute("SELECT status, track, count(*) AS n FROM candidates GROUP BY status, track ORDER BY status, track"):
        print(f"{r['status']:<10} {r['track']:<12} {r['n']}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("sync", "analyze", "enqueue", "report", "status"):
        sub.add_parser(name).add_argument("--db", required=True)
    sub.add_parser("smoke").add_argument("--output", required=True)
    enq = sub.choices["enqueue"]
    enq.add_argument("--workflow", required=True)
    enq.add_argument("--max-outstanding", type=int, default=3)
    rep = sub.choices["report"]
    rep.add_argument("--output", required=True)
    rep.add_argument("--id", required=True)
    args = p.parse_args()
    try:
        if args.command == "sync":
            return sync(args.db)
        if args.command == "analyze":
            return analyze(args.db)
        if args.command == "enqueue":
            return enqueue(args.db, args.workflow, args.max_outstanding)
        if args.command == "report":
            return report(args.db, args.output, args.id)
        if args.command == "status":
            return status(args.db)
        if args.command == "smoke":
            return smoke(args.output)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
