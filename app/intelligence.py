"""Deterministic, offline research-intelligence enrichment of public advisories.

Metadata is never executed or used as shell input. Linked commits are leads,
not verified patches, and scored research fit is not severity or novelty.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from urllib.parse import urlsplit

CVE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)
COMPONENT = re.compile(r"\b(qemu|kvm|runc|containerd|moby|docker engine|docker daemon)\b", re.I)
WEAKNESS = re.compile(r"\b(race condition|use.after.free|out.of.bounds|memory corruption|path traversal|symlink|procfs|container escape|vm escape)\b", re.I)
VERSION_FIX = re.compile(r"\b(fixed in|patched in|fixed by|patched by|introduced in|affected versions?|upgrade to|before version)\b", re.I)
HIGH_ACCESS = re.compile(r"\b(control of both containers|control over both containers|custom mount configurations|untrusted user must be able to spawn|requires privileged|must control the host)\b", re.I)
COMMIT = re.compile(r"^/(opencontainers/runc|containerd/containerd|moby/moby|qemu/qemu|torvalds/linux)/commit/([0-9a-fA-F]{7,64})/?$")
URL_PATTERN = re.compile(r"https?://[^\s<>\]\[()\"']{1,500}")
SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_evidence (
 candidate_id TEXT PRIMARY KEY,
 references_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS candidate_intelligence (
 candidate_id TEXT PRIMARY KEY,
 family_key TEXT NOT NULL,
 age_bucket TEXT NOT NULL,
 research_score INTEGER NOT NULL,
 reasons_json TEXT NOT NULL,
 patch_refs_json TEXT NOT NULL,
 related_json TEXT NOT NULL,
 computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS intelligence_family ON candidate_intelligence(family_key);
"""


def normalized_cve(value: str | None) -> str | None:
    if not value:
        return None
    match = CVE.fullmatch(value.strip())
    return match.group().upper() if match else None


def patch_ref(url: str) -> str | None:
    """Recognize only canonical upstream commit paths. No network requests."""
    if not isinstance(url, str) or len(url) > 800:
        return None
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or (parts.hostname or "").lower() != "github.com"
                or parts.username or parts.password or parts.port or parts.query or parts.fragment):
            return None
    except ValueError:
        return None
    m = COMMIT.fullmatch(parts.path)
    return f"https://github.com{m.group(0).rstrip('/')}" if m else None


def extract_patch_refs(refs: list, text: str) -> list[str]:
    urls = [x for x in refs if isinstance(x, str)]
    urls.extend(URL_PATTERN.findall((text or "")[:12000]))
    patches = set()
    for url in urls[:100]:
        p = patch_ref(url.rstrip('.,;'))
        if p:
            patches.add(p)
    return sorted(patches)[:12]


def age_bucket(published: str | None, now: datetime) -> str:
    if not published:
        return "undated"
    try:
        date = datetime.fromisoformat(published.replace('Z', '+00:00'))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        days = (now - date.astimezone(timezone.utc)).days
    except (ValueError, TypeError, OverflowError):
        return "undated"
    if days < -1:
        return "future-dated"
    if days <= 365:
        return "recent"
    if days <= 1095:
        return "established"
    return "historical"


def score_candidate(row: dict, patch_refs: list[str], now: datetime) -> tuple[int, str, list[str]]:
    """Interpretability-first research-fit score, not vulnerability severity."""
    title = (row.get('title') or '')[:500]
    body = (row.get('summary') or '')[:8000]
    age = age_bucket(row.get('published'), now)
    score, reasons = 30, ['In-scope component matched by advisory ingestion (+30)']
    if COMPONENT.search(title):
        score += 20
        reasons.append('Component named in title (+20)')
    if WEAKNESS.search(title + '\n' + body):
        score += 10
        reasons.append('Isolation or memory-safety weakness described (+10)')
    if VERSION_FIX.search(body):
        score += 12
        reasons.append('Version or patch guidance present (+12)')
    if patch_refs:
        score += 12
        reasons.append('Upstream commit URL present; unverified (+12)')
    if age == 'recent':
        score += 8
        reasons.append('Published within approximately one year (+8)')
    elif age == 'historical':
        score -= 6
        reasons.append('Historical publication; reduced immediate priority (-6)')
    elif age == 'future-dated':
        reasons.append('Future publication date; verify source metadata')
    if HIGH_ACCESS.search(body):
        score -= 12
        reasons.append('Advisory describes high prerequisite access (-12)')
    return max(0, min(score, 100)), age, reasons


def analyze(conn, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    rows = [dict(r) for r in conn.execute('SELECT * FROM candidates ORDER BY id')]
    data, groups = {}, {}
    for row in rows:
        raw = conn.execute('SELECT references_json FROM candidate_evidence WHERE candidate_id=?',
                           (row['id'],)).fetchone()
        try:
            refs = json.loads(raw[0]) if raw else []
        except (ValueError, TypeError):
            refs = []
        patches = extract_patch_refs(refs, row['summary'])
        score, age, reasons = score_candidate(row, patches, now)
        cve = normalized_cve(row.get('cve'))
        citations = {x.upper() for x in CVE.findall(row['summary'] or '')}
        data[row['id']] = dict(row=row, cve=cve, citations=citations, patches=set(patches),
                               score=score, age=age, reasons=reasons,
                               family=f'cve:{cve}' if cve else f"source:{row['id']}")
        if cve:
            groups.setdefault(cve, []).append(row['id'])

    by_cve, citing_cve, by_patch = {}, {}, {}
    for cid, entry in data.items():
        if entry['cve']:
            by_cve.setdefault(entry['cve'], set()).add(cid)
        for mention in entry['citations']:
            citing_cve.setdefault(mention, set()).add(cid)
        for patch in entry['patches']:
            by_patch.setdefault(patch, set()).add(cid)

    # Preserve active/reviewed work while suppressing only new duplicate work.
    duplicates = 0
    order = {'reviewed': 0, 'queued': 1, 'pending': 2, 'duplicate': 3}
    for group in groups.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda cid: (order.get(data[cid]['row']['status'], 4),
                                    -data[cid]['score'], cid))
        for cid in group[1:]:
            if data[cid]['row']['status'] == 'pending':
                conn.execute("UPDATE candidates SET status='duplicate' WHERE id=? AND status='pending'",
                             (cid,))
                duplicates += 1

    computed = now.isoformat(timespec='seconds')
    for cid, entry in data.items():
        connected = set()
        if entry['cve']:
            connected.update(by_cve.get(entry['cve'], ()))
            connected.update(citing_cve.get(entry['cve'], ()))
        for mention in entry['citations']:
            connected.update(by_cve.get(mention, ()))
        for patch in entry['patches']:
            connected.update(by_patch.get(patch, ()))

        related = []
        for other_id in connected:
            if other_id == cid:
                continue
            other = data[other_id]
            if other['row']['track'] != entry['row']['track']:
                continue
            why = []
            if entry['cve'] and entry['cve'] == other['cve']:
                why.append('same CVE')
            elif ((other['cve'] and other['cve'] in entry['citations'])
                  or (entry['cve'] and entry['cve'] in other['citations'])):
                why.append('CVE cited in advisory text; relationship unverified')
            if entry['patches'] & other['patches']:
                why.append('shared upstream commit URL; relationship unverified')
            if why:
                related.append(dict(id=other_id, cve=other['cve'],
                                    source=other['row']['source'], reasons=why))
        related.sort(key=lambda x: (x['cve'] or '', x['id']))
        related = related[:10]

        conn.execute('''INSERT INTO candidate_intelligence
            (candidate_id,family_key,age_bucket,research_score,reasons_json,patch_refs_json,related_json,computed_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(candidate_id) DO UPDATE SET
              family_key=excluded.family_key,age_bucket=excluded.age_bucket,
              research_score=excluded.research_score,reasons_json=excluded.reasons_json,
              patch_refs_json=excluded.patch_refs_json,related_json=excluded.related_json,
              computed_at=excluded.computed_at''',
            (cid, entry['family'], entry['age'], entry['score'],
             json.dumps(entry['reasons']), json.dumps(sorted(entry['patches'])),
             json.dumps(related), computed))
        conn.execute('UPDATE candidates SET score=? WHERE id=?', (entry['score'], cid))
    return {'candidates': len(data), 'duplicates': duplicates}


def report_section(conn, candidate_id: str) -> str:
    row = conn.execute('SELECT * FROM candidate_intelligence WHERE candidate_id=?',
                       (candidate_id,)).fetchone()
    if not row:
        return '## Research intelligence\n\nNot yet analyzed.\n\n'
    reasons = json.loads(row['reasons_json'])
    patches = json.loads(row['patch_refs_json'])
    related = json.loads(row['related_json'])
    section = ('## Research intelligence (metadata-derived)\n\n'
               f"- Publication age: **{row['age_bucket']}**\n"
               f"- Research-fit score: **{row['research_score']}/100** (not CVSS, exploitability, or novelty)\n"
               f"- Family key: {row['family_key']} (same CVE only; not proof of a vulnerability family)\n\n")
    section += '### Scoring evidence\n\n' + ''.join(f'- {r}\n' for r in reasons)
    section += '\n### Upstream commit references (unverified)\n\n'
    section += ''.join(f'- {p}\n' for p in patches) if patches else 'No allowlisted upstream commit URLs present.\n'
    section += '\n### Correlated advisories\n\n'
    section += ''.join(f"- {r['cve'] or r['id'][:12]} ({r['source']}): {', '.join(r['reasons'])}\n"
                       for r in related) if related else 'No explicit cross-references in the current local corpus.\n'
    return section + ('\n**Research note:** References are unverified. Do not infer exploitability, '
                      'a new vulnerability, or a working fix.\n\n')
