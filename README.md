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

## Next implementation milestones

1. Add image/configuration scanners in a separate low-privilege test environment (e.g., offline Trivy SBOM scans); pin versions and isolate image inputs.
2. Add an approved QEMU source-build and regression-test worker with time/memory limits, a trusted source mirror, and known non-disruptive fixtures.
3. Add fuzzing campaigns (ASan/UBSan) with dedicated corpora and hard quotas **after provider approval**. Run untrusted code and potential isolation-boundary validation only in a suitably isolated environment.
4. Add crash fingerprints, triage artifacts, failed-run reconciliation, disk cleanup, health alerts, and a findings dashboard. Docker/container escape validation must not execute against the VPS host.

No persistent ChatGPT connection is required. The server continues discovery, and you can ask ChatGPT to review resulting reports when you choose.

## GitHub workflow

The `main` branch documents the project, while proposed code changes should be reviewed through pull requests. CI runs offline coordinator tests and syntax checks. The repository is safe to publish only because it does not contain credentials, host inventories, or private research artifacts. Keep research findings private until they have been assessed for disclosure.
