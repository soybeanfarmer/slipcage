# Slipcage — Isolation Security Research Lab (starter v0.1)

Slipcage provides automated **metadata-only** research discovery for QEMU/KVM and container runtimes, using a non-root [Dagu](https://docs.dagu.sh/) worker, SQLite, and Ansible. Designed for a ServaRica V3 KVM FAT Slice 6 (6 vCPU / 12 GiB RAM) with Ubuntu Server 24.04 LTS x86-64. No Hetzner/Kimsufi credentials or Hetzner API needed.

**Current feature boundary:** Installs a working dashboard, polls GitHub Advisory and NVD public feeds, filters QEMU/KVM/runc/containerd/Moby/Docker Engine candidates, enqueues reviews, and generates metadata-only Markdown reports. It **does not yet run** QEMU builds, scanners, fuzzers, PoCs, VM escapes, container escapes, or modified historical kernels. These require later reviewed workflows and explicit provider permission where applicable.

## Before deployment

1. Provision the Ubuntu 24.04 x86-64 instance. Use SSH key authentication and make sure your SSH login has sudo. **Never share private SSH keys, passwords, or provider API tokens in chat.**
2. Read `SECURITY.md`. Confirm the provider permits sustained CPU-intensive fuzzing and the intended testing; do not target shared hosting infrastructure.
3. On your administrative Linux/macOS workstation, install `ansible-core` (recommended 2.16 or newer). Use an SSH tunnel for the web dashboard, not a public firewall port.
4. Copy `inventory/hosts.ini.example` to `inventory/hosts.ini` and replace the host IP and SSH login user with your actual values.

## Deploy from your workstation

```bash
cp inventory/hosts.ini.example inventory/hosts.ini
$EDITOR inventory/hosts.ini
ansible-playbook -i inventory/hosts.ini playbooks/site.yml
```

If SSH requires a different identity, use `--private-key /path/to/your/id_ed25519`. If the login requires a sudo password, use `--ask-become-pass`. Do not paste private keys or passwords into configuration files.

The playbook does **not** change SSH configuration or enable UFW; configure a provider firewall and SSH hardening separately once you have verified access. Dagu binds to `127.0.0.1` only.

The installer downloads a **specific official Dagu release** (`2.18.1`, Linux amd64) and verifies the exact published SHA-256 checksum. See `group_vars/all.yml`. It installs common compilers, QEMU packages, and debugger tools, but doesn't execute experiments.

## Access the dashboard securely

Run this on your laptop or workstation (substitute server IP and account):

```bash
ssh -N -L 8525:127.0.0.1:8525 ubuntu@SERVER_IP
```

Visit `http://127.0.0.1:8525/setup` **on your own computer** and create your first Dagu admin. Dagu's built-in authentication is enabled and the account setup is interactive; no administrator password is stored in Ansible.

If you are accessing from your phone rather than a computer, use a securely configured private network or SSH client that supports port forwarding. Do not open TCP 8525 to the public Internet.

## Initial checks on the server

```bash
sudo systemctl status isolab-dagu.service --no-pager
sudo journalctl -u isolab-dagu -n 100 --no-pager
sudo /opt/isolab/app/isolab.py --help
sudo -u isolab env DAGU_HOME=/var/lib/dagu DAGU_DAGS_DIR=/var/lib/dagu/dags \
  /usr/local/bin/dagu validate /var/lib/dagu/dags/smoke.yaml
sudo -u isolab env DAGU_HOME=/var/lib/dagu DAGU_DAGS_DIR=/var/lib/dagu/dags \
  /usr/local/bin/dagu start /var/lib/dagu/dags/smoke.yaml
sudo cat /srv/isolab/reports/smoke-ok.json
/opt/isolab/verify-server.sh
```

`verify-server.sh` reports `/dev/kvm` and CPU flags, but **does not prove** nested virtualization will function reliably. KVM behavior must be tested separately with an isolated non-malicious guest after the provider confirms supported use.

For immediate advisory discovery, run the `discover` DAG manually in Dagu's web UI. It is also scheduled every six hours. A successful run creates `research.sqlite3`, enqueues up to three advisory-review jobs, and generates Markdown reports under `/srv/isolab/reports/`. The `review-candidate` workflow is metadata-only; it is not a vulnerability validation workflow.

## Automated local backups (v0.2.1 proposal)

A new root-only systemd timer creates daily SQLite online snapshots and a
bounded report archive. It verifies both, preserves 14 successful backup sets,
and does not remove previous sets when a run fails. The service is deployed
only through a separately approved GitHub release; there is no automatic
destructive restore. See [Backup operations and limitations](docs/BACKUPS.md).
**Same-VPS copies are not off-server disaster recovery** and omit Dagu history
and future fuzzing corpora.

## v0.3 Reliability and Recovery (proposed)

New candidate reviews use SQLite-persisted delivery attempts and a
15-minute guarded recovery timer. Old queued Dagu deliveries are safely
fenced by a new token after timeouts. Workers that can still be identified
as alive are never preempted. Legacy untracked jobs and ambiguous
process states are surfaced for manual review rather than retried blindly.
A non-destructive restore drill verifies the existing daily backup
by reconstructing it in a separate directory. **No destructive automatic
restore, reboot, exploit execution, or automatic release is added.**

See [Recovery operations](docs/RECOVERY.md). The installed v0.2.1 release
remains unchanged until a later manual production approval.

## v0.4 Research Environment Readiness (proposal)

Proposes **manual-only** nested-KVM capability checks and a harmless disposable
Linux microguest boot test. QEMU runs under a dedicated unprivileged systemd
sandbox, with no guest disks or networking, explicit CPU/RAM/time limits,
and no automatic VM workloads. Neither test runs during deployment.

An optional encrypted **off-server** backup runner uses Restic, but its
timer is intentionally disabled until a separate destination, credentials,
verified host identity and remote restore check are configured. No remote
storage subscription or paid VPN is required by the local research stack;
off-server capacity must be supplied independently.

See [Research Environment Readiness](docs/ENVIRONMENT_READINESS.md) for
safety boundaries, manual checks and offsite setup. Production stays on
v0.3.0 until a reviewed and explicitly approved release.

## v0.5 Safe Experiment Infrastructure (proposed)

Adds a **manual-only** guest lifecycle service for one to five sequential
runs of Slipcage's existing benign, diskless, networkless KVM Linux
microguest. The service is unprivileged and systemd-sandboxed, with
process-group cleanup on timeouts, private per-cycle logs and JSON
summaries, and bounded 20-run retention. No fuzzing, scanning, host escape
workflows, or unattended guest schedules are activated.

See [Guest lifecycle operations and safety boundaries](docs/GUEST_LIFECYCLE.md).
**Encrypted off-server backup setup is intentionally deferred**; the
existing daily local SQLite/report backups remain enabled, but do not
include disposable guest-cycle logs.

## v0.6 Controlled Experiment Foundation (proposed)

Introduces a **fixed, offline, benign arithmetic and SHA-256 known-answer
workload inside Slipcage's disposable nested Linux guest**. The host
verifies exact guest evidence and QEMU shutdown, captures CPU time and peak
QEMU resident memory, and reuses the existing bounded lifecycle cleanup,
single-run concurrency guard, and private per-cycle logs.

Only manual, sequential tests are supported (up to 3 cycles). No fuzzing,
scanning, dynamic guest scripts, Dagu experiment jobs, or autonomous VM
execution is activated. [Controlled Experiment Operations](docs/CONTROLLED_EXPERIMENTS.md).

Your existing local backups remain unchanged. Encrypted off-server backup
setup remains deferred, and these disposable experiment logs are not
included in the daily backups.

## v0.7 Experiment Observability and Safety (proposed)

Adds **manual read-only audits** of disposable guest runs, with per-cycle
evidence consistency checks, SHA-256 fingerprints, deterministic Markdown
and JSON summaries, and identification of possibly active versus
interrupted/incomplete runs. New runs record a manifest before launching
a guest and classify failures without relaxing existing timeouts or
resource quotas.

A passive systemd quota checker detects unexpected configuration changes
**without allocating guest CPU/memory or starting QEMU**. See
[Experiment Observability](docs/EXPERIMENT_OBSERVABILITY.md) for operator
commands and limits.

No guest workload schedules, fuzzing, security-boundary tests, automated
cleanup of interrupted runs, or encrypted off-server backups are added.
Local backups and metadata-only research jobs continue unchanged.

## v0.8 Controlled Failure Recovery (proposal)

Adds a **manual-only, guest-free** drill for process-group timeout
cleanup, synthetic interrupted report auditing, and reading kernel
cgroup v2 resource limits **without exhausting those limits**.
The new service runs as an unprivileged account, with no KVM access,
no network, bounded CPU/memory/tasks and private isolated records.

See [Controlled Failure Recovery](docs/CONTROLLED_FAILURE_RECOVERY.md)
for operator commands and remaining limitations. No scheduled tests,
new guest experiments, fuzzing or real failure injection are enabled.
Daily local backups remain unchanged; encrypted off-server backups
stay deferred.

## v0.9 Operational Reliability (proposed)

After **reviewed release approval**, a minimal hourly read-only health timer
checks Dagu, existing backup/recovery/deployment timers, disk space,
latest local backup freshness and stale interrupted artifacts. It stores a
private JSON snapshot and emits **local systemd journal warnings on status
changes**. No external alert service or credentials are configured; it
does not restart services or execute guests.

A separate **manual, dry-run-first** tool previews cleanup of only old
**successful synthetic fault-drill** data (older than 30 days; always
retain at least 20 recent completed successful drills). Apply requires
two explicit flags and never touches actual guest evidence, failed runs,
research data or backups.

See [Operational Reliability](docs/OPERATIONAL_RELIABILITY.md).
The original daily local backup remains enabled. Encrypted offsite
backups and risky research remain deferred.

## Useful commands

```bash
# Database summary
sudo -u isolab python3 /opt/isolab/app/isolab.py status --db /srv/isolab/research.sqlite3

# Inspect recent logs
sudo journalctl -u isolab-dagu --since '1 hour ago' --no-pager

# Confirm port is loopback-only
sudo ss -lntp | grep ':8525'

# Inspect reports (avoid publishing sensitive findings automatically)
sudo ls -lha /srv/isolab/reports
```

## Project files

- `playbooks/site.yml`: idempotent bootstrap with pinned downloads and a non-root systemd service.
- `group_vars/all.yml`: RAM/CPU limits and release pin.
- `templates/`: Dagu configuration and hardened service unit.
- `workflows/`: safe discovery, review, and smoke-check DAGs.
- `app/isolab.py`: feed ingestion, SQLite deduplication, scoring, bounded enqueue, and reports.
- `tests/`: offline unit tests; `python3 -m unittest discover -s tests -v`.
- `docs/ARCHITECTURE.md`: current vs. planned deployment phases.

## Safe deployments and GitHub Actions

Slipcage **drains active research before every managed deployment**. All
reviewed Dagu workflows invoke `/usr/local/bin/slipcage-guard run`, holding
a shared POSIX lock for the entire command. Ansible first creates a root-owned
maintenance marker, blocking new research, and waits for existing workers to
release their locks (default: **7200 seconds**). Only then can installed code
change. If draining times out, no installed application files are changed.

Ansible applies pending service restarts, confirms Dagu is active, and removes
maintenance **only after** a successful deployment. If a later installation
step fails, maintenance deliberately stays enabled. Investigate before
manually releasing it:

```bash
sudo /usr/local/bin/slipcage-guard end
```

A new job started during maintenance exits temporarily with status 75.
Dagu may skip scheduled runs and queued metadata reviews might require
reconciliation. Do not enable long-running fuzzing until durable queue
recovery and real deployment integration tests have been completed.
Administrator-created DAGs that bypass `slipcage-guard` are not protected.

An unguarded existing installation must be migrated manually after confirming
all its jobs are idle. Fresh servers install the barrier before Dagu starts.

### Zero-cost, self-contained pull-based deployment

The VPS polls GitHub's **latest published stable release** over outbound HTTPS
every 15 minutes using a native `systemd` timer. It accepts only version
tags on `main` with a successful GitHub Actions `validate` check on the
release's exact commit. It then calls Ansible locally and uses the existing
maintenance/drain guard. GitHub never opens a connection into the VPS.

A maintainer explicitly approves each deployment by publishing a stable
GitHub Release using the `Approve Slipcage Release` manual workflow on
`main`, optionally gated by the `production` GitHub Environment.

There is **no VPN, Tailscale, GitHub SSH deployment key, webhook, public
dashboard, or permanent GitHub Actions runner**.

#### One-time bootstrap on the new Ubuntu 24.04 VPS

After the PR is merged into `main`, connect via your usual administrative
SSH session (or the provider console):

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/soybeanfarmer/slipcage.git
cd slipcage
# Review this root-level installer before running it.
sudo bash scripts/bootstrap-pull.sh
```

This installs a root-owned `slipcage-pull-deploy.timer`, its service, a local
Ansible inventory, and the updater. Nothing is deployed until an approved
release is published. To check or initiate polling:

```bash
systemctl list-timers slipcage-pull-deploy.timer
sudo systemctl start slipcage-pull-deploy.service
sudo journalctl -u slipcage-pull-deploy.service -n 100 --no-pager
```

GitHub → Actions → `Approve Slipcage Release` → Run workflow from `main`,
enter a version such as `v0.1.0`, and approve the `production` environment
if configured. Review CI before publishing and protect releases/tags and
the `main` branch against unauthorized modification.

The server pins deployment to a Git commit and stores the last successful SHA
in `/var/lib/slipcage/deployed-sha`. If the updater cannot check GitHub,
the release is not on `main`, the CI check is absent, or the deployment fails,
the VPS does not advance its successful-release marker. Research continues
with the existing installation or remains in maintenance on a post-drain
failure. This is a starting design, **not** a complete rollback mechanism.

Do not activate unsafe, long-running workloads until on-server deployment
tests, durable queue reconciliation, and recovery verification are complete.

## Operations / controls

- No Docker daemon socket, privileged container, dynamic shell from advisory metadata, SSH keys in repository, or automatic exploit execution.
- Dagu's `research` queue permits only one active candidate-review workflow. Discovery maintains at most three outstanding queued reviews; stuck items require manual intervention in v0.1.
- GitHub API anonymous queries may be rate-limited; NVD can throttle. One feed may fail without aborting the other. A total feed outage causes the discovery workflow to fail visibly.
- The metadata scorer is a heuristic and will miss advisories; results must not be treated as authoritative vulnerability claims.
- Workflows are version controlled. Changes to execution behavior require normal code review, not AI-generated unsupervised steps.
- Back up `/var/lib/dagu` and `/srv/isolab` using a private, access-controlled backup destination. Apply OS security updates regularly and perform a tested restoration before enabling real experiments.

## Research intelligence (v0.2 proposal)

The planned v0.2 upgrade adds deterministic, offline research-fit scores,
historical/established/recent labels, same-CVE deduplication across advisory
feeds, and metadata-only links based on explicit CVE citations or shared
allowlisted upstream commit URLs. These are **unverified leads**, not
vulnerability reproductions or verified patches. The workflow remains
metadata-only and the Dagu deployment lock remains intact.

See [Research Intelligence](docs/RESEARCH_INTELLIGENCE.md) for migration,
backups, new report fields and limitations. v0.1.0 remains the production
release until this pull request is reviewed, merged and explicitly released.

## Next implementation milestones

1. Add image/configuration scanners in a separate low-privilege test environment (e.g., offline Trivy SBOM scans); pin versions and isolate image inputs.
2. Add an approved QEMU source-build and regression-test worker with time/memory limits, a trusted source mirror, and known non-disruptive fixtures.
3. Add fuzzing campaigns (ASan/UBSan) with dedicated corpora and hard quotas **after provider approval**. Run untrusted code and potential isolation-boundary validation only in a suitably isolated environment.
4. Add crash fingerprints, triage artifacts, failed-run reconciliation, disk cleanup, health alerts, and a findings dashboard. Docker/container escape validation must not execute against the VPS host.

No persistent ChatGPT connection is required. The server continues discovery, and you can ask ChatGPT to review resulting reports when you choose.

## GitHub workflow

The `main` branch documents the project, while proposed code changes should be reviewed through pull requests. CI runs offline coordinator tests and syntax checks. The repository is safe to publish only because it does not contain credentials, host inventories, or private research artifacts. Keep research findings private until they have been assessed for disclosure.
