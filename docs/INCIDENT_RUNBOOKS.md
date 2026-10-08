# Slipcage operational incident runbooks (v0.10)

**First principles:** retain evidence and avoid compounding problems.
Do not reboot the VPS, delete evidence or backups, change service
quotas, run QEMU, enable fuzzing, or force a deploy as a first response.
An incident warning is not proof of corrupted research results.
All examples below are read-only unless explicitly marked.

## Quick assessment — no modifications

    sudo systemctl status slipcage-health.timer --no-pager
    sudo journalctl -u slipcage-health.service -n 60 --no-pager -l
    sudo cat /var/lib/slipcage-health/status.json
    sudo systemctl --failed --no-pager
    df -h /

Review the "issues" array in the latest health JSON. The hourly
check logs every snapshot and emits SLIPCAGE_HEALTH_WARNING only when
the issue set changes; SLIPCAGE_HEALTH_RECOVERED follows resolution.
An "inactive" one-shot service is **not** itself a failure when its
timer is active. Do not infer remote notification delivery from the
presence of a local warning: HTTPS delivery is opt-in and disabled by
default.

## 1. Local backup missing, stale, invalid, or failed restore assurance

    sudo systemctl status slipcage-backup.timer --no-pager
    sudo journalctl -u slipcage-backup.service -n 60 --no-pager -l
    sudo ls -la /var/backups/slipcage
    sudo cat /var/lib/slipcage-assurance/status.json
    sudo journalctl -u slipcage-assurance.service -n 50 --no-pager -l
    df -h /

A "recent_manifest_present" condition only establishes that a backup
directory and well-formed manifest exist, not that restoration works.
The weekly scratch restore verifies real local backups under bounded
CPU, memory, time and scratch disk. If it reports failure, do **not**
replace the research SQLite database, lower retention, or alter
existing backup snapshots. Diagnose disk space, backup size gates,
integrity errors and incomplete scratch leftovers. Escalate
before rerunning a costly restore repeatedly. A backup is still
on this same VPS, so VPS loss remains an uncovered scenario;
encrypted off-server backups remain deferred by request.

## 2. Disk space or filesystem pressure

    df -h /
    df -i /
    sudo du -sh /var/backups/slipcage /var/lib/slipcage-guest \
      /var/lib/slipcage-fault /var/cache/slipcage-assurance 2>/dev/null

If space is unexpectedly low, identify the largest growth source.
Do not blindly purge local backup snapshots or incomplete run
evidence. The manual fault-retention tool may show a **dry-run**
preview for completed successful *synthetic fault drills only*:

    sudo -u slipcage-vmprobe python3 \
      /usr/local/lib/slipcage/fault-retention.py

Deletion still requires separate operator review and explicit apply
flags. The default health timer never deletes files.

## 3. Interrupted guest run or unexpected VM probe status

    sudo systemctl status 'slipcage-experiment@1.service' --no-pager
    sudo journalctl -u 'slipcage-experiment@1.service' -n 60 --no-pager -l
    sudo -u slipcage-vmprobe python3 \
      /usr/local/lib/slipcage/experiment-audit.py --limit 20 --format json

The auditor distinguishes interrupted/incomplete from possibly active
and checks the existing flock. Preserve logs and the partial
run.json/summary evidence. Do not restart or forcibly kill a VM
based on this read-only audit alone; check whether another reviewed
manual experiment is still in progress. No automatic guest execution
or fault injection is enabled.

## 4. Pull deployment failure or wrong deployed SHA

    sudo systemctl status slipcage-pull-deploy.timer --no-pager
    sudo journalctl -u slipcage-pull-deploy.service -n 80 --no-pager -l
    sudo cat /var/lib/slipcage/deployed-sha
    sudo systemctl --failed --no-pager

Compare the SHA with the expected approved tag/commit in GitHub.
Do not try to bypass the review/approval gate, manually change the
deployed SHA file or run an unreviewed branch on production.
Capture relevant logs and request review before reattempting.

## 5. Dagu, review-recovery, or scheduled service failure

    sudo systemctl status isolab-dagu.service --no-pager
    sudo systemctl status slipcage-recover.timer --no-pager
    sudo journalctl -u isolab-dagu.service -n 60 --no-pager -l
    sudo journalctl -u slipcage-recover.service -n 60 --no-pager -l

Prioritize understanding whether the metadata-only research database
has valid reviews and whether an existing guard/maintenance lock is
active. Do not delete SQLite locks, rebuild the DB or restart several
services at once. Preserve the journal and trigger the existing
approved recovery workflow only after understanding the root cause.

## 6. Missing or failed external incident notifications

    sudo python3 /usr/local/lib/slipcage/alert-dispatch.py
    sudo systemctl status slipcage-alert-dispatch.timer --no-pager
    sudo journalctl -u slipcage-alert-dispatch.service -n 50 --no-pager -l

The dispatcher preview is entirely local and non-transmitting.
An inactive alert timer is normal until the user authorizes an HTTPS
webhook and explicit opt-in. Do not paste URL credentials or complete
webhook URLs into a public issue, logs or conversation. After separate
authorization, investigate recent health snapshot freshness, the
endpoint's supported JSON schema and HTTP 2xx acknowledgement.
Delivery is at least once, not guaranteed exactly once; remote
endpoint outages are not silently treated as successful delivery.

## Escalation checklist

Record UTC time, approved deployed SHA, affected unit/timer, exact
non-secret health issue codes, and the earliest relevant error line.
Share only redacted excerpts. Never share SSH keys, tokens, provider
credentials, SQLite contents, backup archives, private guest logs,
or webhook secret URLs. Do not grant additional resource or KVM
permissions simply to silence a monitoring warning.
