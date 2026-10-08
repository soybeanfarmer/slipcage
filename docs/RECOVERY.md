# Slipcage v0.3 — Review queue recovery and restore drills

Slipcage v0.3 keeps **SQLite as the durable record of review work**.
Dagu handles delivery and scheduling but does not decide whether a review
attempt is still authorized. No exploit execution or active testing is added.

## Delivery states and crash recovery

- New review candidates are claimed atomically in SQLite, with an opaque
  32-character attempt token and a maximum of 3 outstanding reviews.
- Dagu receives only the candidate's opaque SHA-256 ID and a token.
  A worker must atomically claim that exact token before writing a report.
- If a queued delivery has not started for 30 minutes, it can be reclaimed.
  A new token invalidates the old queued Dagu request; any late delivery of
  that old token exits successfully without writing anything.
- Running workers record Linux boot ID, process ID and process start tick.
  The recovery worker reclaims a running job only after 2 minutes and when
  it can establish that the original process is no longer alive.
  Live workers are **never** interrupted for a retry.
- Ambiguous process liveness and pre-v0.3 legacy queued work are **not**
  retried automatically. These are reported for operator attention.
- After 3 delivery attempts, a candidate becomes needs_attention instead
  of retrying forever. This is an explicit pause, not silent data loss.
- Reviews use the deterministic name candidate-<full-id>.md, making
  post-crash retries idempotent. Historical report files remain intact.
- A guarded systemd timer checks every ~15 minutes and after reboot.
  The scheduled six-hour discovery workflow also queues new work.
- Reconciliation never creates a privileged container, launches a PoC,
  processes untrusted advisory text as shell, or kills a running job.

**Caveat:** SQLite and Dagu do not share a transaction. This design uses
at-least-once Dagu delivery and token fencing, not exactly-once delivery.
A Dagu request can still appear in its own history after its token expires,
but it is inert. A failed Dagu enqueue may count against the three-attempt
cap. Statuses need operator observation, and this does not repair a damaged
Dagu database or support arbitrarily long unsafe experiments.

## Quick checks after an approved release

    sudo systemctl is-active isolab-dagu.service
    sudo systemctl list-timers slipcage-recover.timer
    sudo systemctl start slipcage-recover.service
    sudo journalctl -u slipcage-recover.service -n 40 --no-pager
    sudo -u isolab python3 /opt/isolab/app/isolab.py status \
      --db /srv/isolab/research.sqlite3

The reconciliation log reports queued_reclaimed, running_reclaimed,
ambiguous_running and legacy_untracked. Zero reclamations on a healthy
system are normal. A oneshot recovery service that exits successfully is
normally inactive (dead) until the next timer run.

## Restore validation (never replace live data)

The backup tool from v0.2.1 retains its daily snapshots. v0.3 installs
a helper that validates and reconstructs an existing snapshot in a NEW,
root-only location.

First choose an actual snapshot directory from:

    sudo ls -ld /var/backups/slipcage/backup-*

Then run, replacing BACKUP_DIRECTORY_NAME with the selected name:

    sudo /usr/local/sbin/slipcage-restore-check \
      --source /var/backups/slipcage/BACKUP_DIRECTORY_NAME \
      --destination /var/backups/slipcage/restore-drill-v0.3

The destination must not already exist. The script validates the
manifest/checksums and SQLite integrity, extracts only vetted regular
report files, and checks the reconstructed database. Inspect its
candidates and reports counts; no source data is overwritten. This
reconstructs backups but **does not perform a live cutover**.

## Still missing before experimental fuzzing

This is a recovery foundation, not full disaster recovery. We still need
provider-authorized workload isolation, real deployment rollback, backup
coverage for Dagu history and future crash corpora, encrypted off-server
backups with distinct credentials, operational alerting, and measured
reboot/power-interruption tests.

Do not conduct a destructive reboot drill on a production host without
first taking separate, verifiable copies and checking for running work.
