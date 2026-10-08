# Slipcage v0.2 — Research Intelligence

This module improves research selection. It does **not** rank exploitability,
estimate CVSS, validate fixes, or detect previously unknown vulnerabilities.

## Processing

The scheduled discovery workflow now executes: sync → analyze → enqueue,
under the existing deployment lock. The analyze command creates two additive
SQLite tables (candidate_evidence and candidate_intelligence), preserving the
existing candidates, statuses, queue and historical reports.

- Research-fit scoring explains components, described weaknesses, version
  guidance, allowed upstream commit references, age and prerequisites.
- Publications are classified recent (≤365 days), established (366–1095),
  historical (older), undated or future-dated. Recent does not mean novel.
- Identical CVEs across GitHub and NVD are grouped. Additional pending copies
  are marked duplicate; previously queued/reviewed work is preserved.
- Distinct CVEs become possibly-related leads only if one advisory explicitly
  mentions the other CVE or both include the same commit URL.
- Commit URL candidates are treated as unverified metadata: no downloads,
  execution, external scanning or code cloning occurs.
- New reports gain age labels, research scoring rationale, candidate commit
  paths and cross-advisory citations. Old reports are not silently replaced.

## First upgrade on the VPS

Back up /srv/isolab/research.sqlite3 privately before the release.
After an approved v0.2 deployment, refresh intelligence for existing items
using the following command on the server:

    sudo -u isolab python3 /opt/isolab/app/isolab.py analyze \
      --db /srv/isolab/research.sqlite3

To regenerate an older report with the intelligence fields:

    sudo -u isolab python3 /opt/isolab/app/isolab.py report \
      --db /srv/isolab/research.sqlite3 --output /srv/isolab/reports \
      --id REPLACE_WITH_EXISTING_64_CHAR_CANDIDATE_ID

New scheduled discoveries execute analysis automatically every six hours.

## Limits

This correlates only advisories in the local database. Shared references
do not prove a common root cause, fix effectiveness or successful escape.
Research scores are transparent heuristics and should be calibrated.
Unsafe experiments remain disabled, and durable queue recovery and
rollback remain prerequisites for unattended long-running research.
