# Slipcage v0.10 — Operational Assurance and Alerting

This release improves the *existing metadata-only operations* without
enabling more workloads. Guest VM execution remains manual. Nothing here
starts QEMU, fuzzes, sends off-VPS backup copies, changes the production DB
or authorizes provider-boundary tests.

## 1. Weekly bounded, local scratch restore of the latest backup

The new slipcage-assurance.timer runs once per week on **Sunday around
04:30 UTC** (up to 90 minutes randomized delay). Its read-only backup
assurance service selects the latest completed backup under
/var/backups/slipcage, verifies SHA-256 files and backup SQLite integrity
using the existing slipcage-restore-check code, restores its SQLite/report
contents into a private temporary cache directory, checks the resulting
SQLite candidate count and report count, then removes only that unique
temporary directory. It **never writes into** /srv/isolab, live reports
or the backup source, and does not change daily backup retention.

The service is network-isolated, no devices, filesystem-protected, with
MemoryMax=512M, CPUQuota=35%, TasksMax=32, LimitFSIZE=768M,
TimeoutStartSec=10min, and low I/O scheduling priority. The runner
fails closed on backed-up DBs above 256 MiB, archives above 512 MiB,
or insufficient scratch disk (requires >2 GiB plus twice input sizes).
These caps may cause a larger future backup to fail assurance; this is
an alert to redesign the resource budget, not permission to discard
or truncate data.

After an approved release, manually establish the initial health record
*before* interpreting v0.10 hourly health alerts:

    sudo systemctl start slipcage-pull-deploy.service
    sudo cat /var/lib/slipcage/deployed-sha
    sudo systemctl start slipcage-assurance.service
    sudo journalctl -u slipcage-assurance.service -n 40 --no-pager -l
    sudo systemctl start slipcage-health.service
    sudo journalctl -u slipcage-health.service -n 40 --no-pager -l

The assurance service writes
/var/lib/slipcage-assurance/status.json, root-private 0600.
Expect passed=true, live_data_modified=false, and a valid backed-up
candidate/report count. Health monitoring now requires a passed restore
status no more than 10 days old. Before the first scratch check, health
will correctly warn restore_assurance:never_checked. If the scratch
check fails, investigate its status and disk capacity rather than
retrying repeatedly. A forced SIGKILL/system crash may leave an
unverified scratch directory requiring *manual* inspection: no
unattended cleanup of unknown residue is added.

This validates a *local backup* but cannot protect against losing
the entire VPS. Encrypted off-server backups remain deferred.

## 2. Optional external incident notifications (OFF by default)

The new alert-dispatch.py is a **transport-neutral generic JSON HTTPS
webhook** client. It reads only the latest root-private health status
(checked no more than 3 hours ago), sends a minimal payload containing
service, warning/recovery type, issue codes and health-check timestamp.
It NEVER sends research records, backup contents, logs, disk metrics,
host addresses, or secret webhook URLs in its JSON output.

It suppresses identical successfully delivered issue sets, sends
a recovery only after an earlier warning was delivered, and saves
the issue signature **only after an HTTPS 2xx** response. Delivery
failure leaves it eligible to retry on the next invocation.
This is *at-least-once*, not a exactly-once transaction: a network
failure after a server has accepted an alert but before the local
receipt could cause a duplicate. No retries run in a tight loop.

Preview without any network traffic or credentials:

    sudo python3 /usr/local/lib/slipcage/alert-dispatch.py

**Do not enable external delivery until you explicitly choose a
compatible HTTPS JSON webhook endpoint and authorize it.**
This requires configuring a root-owned, mode 0600
/etc/slipcage/health-webhook.url containing one operator-provided HTTPS
URL. Never commit it to GitHub, paste it into this chat, or expose it in
logs. A generic webhook must accept this JSON structure; Slack/Discord
and other APIs may require a provider-specific adapter later.

The units slipcage-alert-dispatch.service and its timer are installed
but **NOT enabled, started, or configured by Ansible**. After separate
approval and testing with your chosen endpoint, the operator can
explicitly start the service once and subsequently enable the optional
hourly alert timer. The service itself requires the private endpoint
file and network access. Endpoints must be HTTPS hostnames with
default port 443, no redirects or proxy forwarding; this remains a
network-capable service only if manually enabled.

This workflow does not create an email account, new paid service,
offsite backup, or notification connector automatically.

## 3. Incident response

See [Incident Runbooks](INCIDENT_RUNBOOKS.md) for triage of:
- missing or unverifiable backups and failed scratch restores;
- low disk space;
- interrupted disposable VM experiments;
- failed release pull deployments;
- Dagu/recovery service failures;
- absent/failed alert delivery.

All runbooks use **read-only checks first**. They do not authorize
automatic deletion, forced service restarts, database replacement
or executing new VM/fuzzing payloads.

## Human release gates

1. CI offline tests and service/Ansible review must pass.
2. Merge the PR; manually request and approve v0.10.0 release through
   the existing GitHub workflow.
3. VPS pull-deploy; check deployed SHA.
4. Manually run the bounded assurance once, then inspect hourly
   health status. Do **not** enable notifications merely because
   the health check passed.
5. Choose an alert destination later, if desired, then approve
   endpoint-specific delivery as a separate operational change.

This is not a full disaster recovery service or hypervisor security
assurance. It is deliberately conservative operational evidence.
