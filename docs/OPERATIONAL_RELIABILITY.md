# Slipcage v0.9 — Operational Reliability

v0.9 adds low-impact health monitoring and explicit retention planning for
**completed, successful, synthetic fault-drill artifacts only**. It does not
launch a VM, perform research tests, run a scanner, restart services, send
external requests, or make unapproved deployments.

## Hourly local health monitoring

After a reviewed v0.9 release, the slipcage-health.timer is enabled.
It starts slipcage-health.service approximately hourly, with randomized
delay and a short service timeout. This is a **read-only, root-owned**
service because local backups are accessible only to root. It has no
capabilities, no network, a read-only host filesystem except its own
private status state, 128 MiB memory and 25% CPU caps.

Each check inspects:
- The Dagu research service and existing approved deploy, backup and
  recovery timers; and whether the related oneshot services are in
  systemd's failed state.
- Free disk space on the root filesystem: warn if free is below 1 GiB
  or usage reaches 90%.
- Presence of the latest completed backup and its *manifest shape*,
  with an age of at most **42 hours** to accommodate the existing
  daily timer and randomized delay.
- Whether the current deployed SHA file exists and contains a valid
  Git commit hash.
- Incomplete guest and fault-drill records whose directory mtime is
  over **24 hours**, without touching or removing those records.

The checker stores /var/lib/slipcage-health/status.json (0600),
outputs a full structured JSON status to the **local systemd journal**
each time, and emits SLIPCAGE_HEALTH_WARNING or
SLIPCAGE_HEALTH_RECOVERED on issue-set transitions. A repeated
condition remains visible in JSON every hour but does not generate a
new transition alert every hour.

**Important limitation:** These are LOCAL JOURNAL ALERTS, not
push notifications, emails, SMS or remote incident response. A failed
backup manifest-shape check does NOT prove the backup is restorable.
The prior verified local backup and restore drill mechanisms are still
the appropriate separate controls.

After deployment:

    sudo systemctl status slipcage-health.timer --no-pager
    sudo systemctl start slipcage-health.service
    sudo journalctl -u slipcage-health.service -n 40 --no-pager -l

The health command exits nonzero when a problem is detected. This is
intentional: check its journal JSON rather than masking failures.
For a no-state-change, read-only check:

    sudo python3 /usr/local/lib/slipcage/health.py

To view the latest persisted status:

    sudo cat /var/lib/slipcage-health/status.json

On a genuine warning, investigate and repair that condition. The
health checker does **not** automatically restart services, prune
databases, change backups, or suppress legitimate systemd failures.

## Conservative synthetic-artifact retention

The new slipcage-fault-retention.py tool checks only the disposable
**synthetic** fault drill directory /var/lib/slipcage-fault.
It is not scheduled, and its default behavior is a **dry-run preview**.

A drill directory is only eligible for cleanup when:
- it matches the existing fixed drill name pattern;
- it has a complete, successful summary with no QEMU execution
  or live-data modification;
- its records contain only recognized, small, regular files and
  directories, not symlinks or unexpected file types;
- it is **older than 30 days**; and
- it is outside the most recent **20 completed successful** drill
  directories.

Incomplete, interrupted, failed and unsafe entries remain preserved.
The tool takes the existing fault-drill flock lock, refuses overlapping
fault drills, and aborts on unexpected directory structures.
It never accesses local backups, guest-run evidence, research DBs
or report corpora.

Preview:

    sudo -u slipcage-vmprobe python3 /usr/local/lib/slipcage/fault-retention.py

Only after reviewing the exact eligible directories, an operator may
explicitly apply the same conservative policy:

    sudo -u slipcage-vmprobe python3 /usr/local/lib/slipcage/fault-retention.py --apply --confirm

There is no automatic cleanup timer or unattended deletion. This
protects diagnostic evidence and prevents a bug from silently erasing
valuable run records.

## Remaining limits and release gates

- Deploy through GitHub CI, review, release approval and the existing
  VPS pull-deployer, exactly as previous versions.
- Before calling v0.9 production-validated, inspect one live health
  JSON check and a fault-retention dry-run preview on the VPS.
- These checks do not perform a backup restore; prior restore drill
  controls still apply.
- Encrypted off-server backups remain deferred, as requested; local
  backups cannot recover from loss of the entire VPS.
- Fuzzing, malicious guest experiments, provider boundary testing and
  any unattended VM execution remain disabled.
