#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 /opt/isolab/app/isolab.py sync --db /srv/isolab/research.sqlite3
/usr/bin/python3 /opt/isolab/app/isolab.py enqueue --db /srv/isolab/research.sqlite3 --workflow /var/lib/dagu/dags/review-candidate.yaml --max-outstanding 3
