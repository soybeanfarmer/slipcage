# Automatic research backups (v0.2.1)

Slipcage backs up its research queue and reports **on the VPS** after an
approved v0.2.1 release. The installation creates a root-owned private
directory at /var/backups/slipcage (mode 0700), a systemd oneshot service,
and a daily timer.

## Schedule and coverage

- Daily around 03:15–04:00 UTC (randomized), including catch-up following
  a reboot when systemd's persistent timer detects a missed run.
- A consistent, non-destructive snapshot of
  /srv/isolab/research.sqlite3 using Python's SQLite online backup API.
  This works while discovery and report jobs are active, including WAL mode.
- A best-effort archive of regular files directly under
  /srv/isolab/reports, with a 128 MiB per-file and 512 MiB total cap.
  The report archive is not transactionally synchronized to the database.
- A SHA-256 manifest covering the database and report archive; verifies
  content, opens the backup DB with SQLite integrity_check and reads the
  archive before publishing the backup directory.
- Retains the 14 most recent successfully verified backup sets. Failed runs
  do not delete older backups. A separate root lock prevents overlapping runs.
- Backup timer/service is independent of Dagu and does not block the
  deployment/research guard. Source database is never modified by the helper.

These backups do NOT include /var/lib/dagu workflow history, VPS OS state,
SSH keys, provider configuration, or any future fuzzing crash corpus outside
the reports directory. Directory nesting and symlinks in reports are rejected
rather than silently omitted. All of these limits must be revisited before
enabling large-scale fuzzing.

## Operations

After first deployment, trigger and inspect one full backup:

    sudo systemctl start slipcage-backup.service
    sudo systemctl status slipcage-backup.service --no-pager
    sudo journalctl -u slipcage-backup.service -n 50 --no-pager
    sudo systemctl list-timers slipcage-backup.timer

List completed backups and inspect one:

    sudo ls -ld /var/backups/slipcage/backup-*
    sudo /usr/local/sbin/slipcage-backup verify \
      /var/backups/slipcage/BACKUP_DIRECTORY_NAME

An inactive (dead) state is normal for a successful oneshot backup service;
look for status=0/SUCCESS and a verified snapshot in the logs.

## Restore planning

Verify a selected backup before considering recovery. Never restore it
over a live SQLite database or active workflow. Stop or drain research
jobs and take a separate safety copy of the current state first. Restore
the snapshot and selected reports to an isolated staging directory, check
their integrity, and only then perform a documented manual cutover. There
is intentionally **no unattended destructive restore command**.

## Important limitation: local storage

Local backups are valuable against deletion or corruption of the database,
but **not** against loss of the entire VPS, disk, provider, or account.
The backup copies share the same storage failure domain as the original.
Before collecting expensive or unpublished research findings, add encrypted
off-server backups with independent access controls and a tested restore
process. Do not commit research archives to the public GitHub repository.
