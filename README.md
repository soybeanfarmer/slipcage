# Slipcage

**Know what broke before you upgrade.**

Slipcage is evolving from an autonomous infrastructure security research lab into a **reproducible infrastructure security regression testing platform**. Its core question is: **When infrastructure changes, does its security behavior change too?**

The planned product will run reviewed, non-destructive security assertions against pinned, disposable environments, compare baseline and candidate behavior, and generate evidence-backed reports. The initial target is **Kubernetes (K3s first), container runtimes, and infrastructure security**.

**Important: the product described above is the direction, not a claim that the hosted platform or Kubernetes regression engine already exists.** The latest published repository release at the v0.11 planning baseline was [v0.10.0](https://github.com/soybeanfarmer/slipcage/releases/tag/v0.10.0). A published release or passing GitHub CI does not prove which SHA is running on the VPS or that a live guest has passed verification.

## Status: existing lab vs. planned product

| Capability | Implemented in repository | Not yet established |
| --- | --- | --- |
| Research intelligence | GitHub Advisory/NVD metadata ingestion, scoring, SQLite state, guarded Dagu review queue | Verified vulnerability reproduction |
| Deployment and operations | Ansible/systemd, reviewed GitHub releases, outbound release polling, drain guard, local backup and scratch-restore assurance, passive health checks | Universal unattended recovery; verified independent disaster recovery |
| Disposable VM foundation | Manual-only, bounded QEMU/KVM benign microguest boot and fixed arithmetic/SHA-256 test, private JSON/log evidence and audits | Dedicated K3s VMs; VM-based security assertions; hostile-code isolation |
| Experiment engine | Offline versioned spec, typed results, synthetic fixture runner/bundles/comparison/reports; existing fixed benign VM profile | Real Kubernetes adapter, verified security observations and replay |
| Hosted application | None | React dashboard, Cloudflare API/D1/R2, distributed worker leases and multi-tenant authorization |

Current documentation and tests establish implemented code paths, not live production results. See [current vs. target architecture](docs/ARCHITECTURE.md), [product vision](docs/PRODUCT_VISION.md), [v1 milestones](docs/V1_ROADMAP.md), and [experiment interface proposal](docs/EXPERIMENT_CONTRACT.md).

## Principles and scope

- **Behavior, not configuration alone:** verify observed allow/deny/isolation results, not just YAML or scanner findings.
- **Reproducible:** pin versions and inputs; preserve normalized results, provenance and evidence.
- **Differential:** execute the same approved assertion against a baseline and a candidate; classify infrastructure failures separately from security regressions.
- **Safe by default:** explicitly authorized, resource-bounded, disposable execution; separate the public control plane from workers and guest environments.
- **Open core, hybrid execution:** preserve a portable self-hosted runner, then add a hosted control plane and optionally customer-controlled execution workers.
- **Incremental:** do not replace proven Python, SQLite, Dagu, systemd, Ansible or QEMU/KVM foundations without a concrete need.

**Not v1 scope:** vulnerability scanning as the core product, general penetration testing, public user-supplied shell/Python execution, fuzzing, VM-escape reproduction, or experiments against a hosting provider's infrastructure.

## Existing lab deployment (current v0.x operations)

Existing deployments target Ubuntu Server 24.04 x86-64 on a permitted ServaRica VPS. These commands apply to the **existing metadata-research lab**, not a Kubernetes regression platform.

1. Read [SECURITY.md](SECURITY.md). Confirm provider terms for any intended nested VM work. Never share SSH keys, provider tokens, or passwords in a repository, issue, or chat.
2. Install Ansible on your administrative workstation, copy `inventory/hosts.ini.example` to the ignored `inventory/hosts.ini`, and enter your actual host and SSH user.
3. For an initial workstation-driven bootstrap, run:

   ~~~bash
   ansible-playbook -i inventory/hosts.ini playbooks/site.yml
   ~~~

The installer does not automatically change SSH firewall settings. The existing Dagu dashboard binds to `127.0.0.1:8525`. Access it over an SSH tunnel, **not** an opened public port:

~~~bash
ssh -N -L 8525:127.0.0.1:8525 YOUR_SSH_USER@YOUR_SERVER
~~~

Open `http://127.0.0.1:8525/setup` locally to complete Dagu's interactive administrator setup. Dagu access can execute workflows as its service user; treat administrative workflow editing as shell-equivalent for that user.

### Approved release and VPS verification

All production promotion requires an explicit human decision. Source merged to `main` is **not** automatically deployed. The approved GitHub release workflow publishes a version tag from `main`; the VPS-side systemd pull-deployer checks the release and CI before applying Ansible changes through the drain guard.

After the human operator merges the reviewed PR and **separately approves/publishes the release**, the operator may use:

~~~bash
sudo systemctl start slipcage-pull-deploy.service
sudo cat /var/lib/slipcage/deployed-sha
~~~

Compare the displayed SHA to the exact approved release commit. A successful release workflow alone does not establish that the VPS applied it. Additional milestone-specific systemd/journal checks and operator review are mandatory before marking a runtime milestone production-validated. See [controlled development workflow](docs/DEVELOPMENT_WORKFLOW.md).

The current operational assurance checks (already implemented in v0.10) can be run **manually by the operator after verifying deployment**, without enabling external integrations:

~~~bash
sudo systemctl start slipcage-assurance.service
sudo journalctl -u slipcage-assurance.service -n 40 --no-pager -l
sudo systemctl start slipcage-health.service
sudo journalctl -u slipcage-health.service -n 30 --no-pager -l
~~~

The expected success evidence for local scratch-restore assurance includes `passed: true` and `live_data_modified: false`, plus a successful service exit. Inspect actual journal output; do not infer success from this README. Local backup/restore assurance is **not off-server disaster recovery**.

### Existing command-line and workflow entry points

- `app/isolab.py`: metadata research candidate state, discovery and reports.
- `app/intelligence.py`: deterministic, metadata-only advisory relevance evidence.
- `app/recovery.py`: persisted delivery/recovery for Dagu review jobs.
- `scripts/slipcage-guest-lifecycle.py`: manually invoked, fixed-profile benign guest tests, with bounded evidence retention.
- `scripts/slipcage-experiment-audit.py`: read-only private guest evidence audit.
- `scripts/slipcage-health.py`, `scripts/slipcage-backup.py`, `scripts/slipcage-assurance.py`: operational checks.
- `playbooks/site.yml`, `systemd/`, `workflows/`: deployed infrastructure.

Current KVM tests are explicitly manual and non-adversarial; CI constructs guest images but does **not** boot QEMU or K3s.

## Offline experiment contract CLI (first v0.12 code milestone)

The separately installable `slipcage-engine` package introduces a **read-only**
`slipcage validate` command. It verifies small YAML/JSON experiment definitions
against a packaged v1alpha1 JSON Schema, rejects unknown profiles and unsafe
or ambiguous syntax, and prints a deterministic SHA-256 of canonicalized data.

~~~bash
python3 -m pip install -e .
slipcage validate examples/experiments/rbac-pod-create-denied.yaml --json
# Alternatively: python3 -m slipcage_engine validate ... --json
~~~

The offline Python library also exposes immutable typed assertion outcomes
(`PASS`, `FAIL`, `ERROR`, `SKIP`, `INCONCLUSIVE`) for SC-07. Those
outcomes can be constructed from synthetic, typed observations, but are **not**
evidence that Kubernetes was contacted or that any security assertion ran.
See [typed outcome limitations](docs/ENGINE_CLI.md).

The SC-08 `slipcage run-fixture` subcommand can simulate the existing
typed outcomes using a **fixed, packaged offline** RBAC observation table:

~~~bash
slipcage run-fixture examples/experiments/rbac-pod-create-denied.yaml --scenario denied --json
~~~

Results explicitly say `simulated: true`,
`security_test_executed: false`, and `evidence_status: not_collected`.
This does not contact a Kubernetes API, launch a VM, or constitute verified
security behavior. See [offline fixture execution](docs/ENGINE_CLI.md).

SC-09 adds a local synthetic bundle writer/verifier, preserving only
simulated results with bounded canonical JSON and private checksum-checked
artifacts:

~~~bash
slipcage bundle-fixture examples/experiments/rbac-pod-create-denied.yaml \
  --scenario denied --output ./new-synthetic-bundle --json
slipcage verify-bundle ./new-synthetic-bundle --json
~~~

You can also compare two **independently created synthetic fixture bundles**
without executing a real workload:

~~~bash
slipcage compare-fixtures ./baseline-fixture ./candidate-fixture --json
~~~

A synthetic baseline PASS and candidate FAIL is labeled `regression`;
missing, damaged or incompatible bundles are `incomparable` instead.
The generic real-environment `compare` command remains unavailable.

SC-11 now offers read-only JSON/Markdown reports and a one-command, completely
synthetic offline proof:

~~~bash
scratch="$(mktemp -d)"
slipcage demo-fixtures examples/experiments/rbac-pod-create-denied.yaml \
  --baseline-scenario denied --candidate-scenario allowed \
  --output "$scratch/proof" --json
slipcage verify-demo "$scratch/proof" --json
~~~

Both commands intentionally exit 1 when they detect the seeded synthetic
regression. The private proof includes two independently checked bundles,
`report.json`, `report.md`, and a final completion manifest. This is
**not** a live security finding or a Kubernetes test. For read-only output from
existing bundles, use `slipcage report-fixtures BASELINE CANDIDATE --format markdown`.
See [offline proof and reports](docs/ENGINE_CLI.md).

Verification confirms local integrity and replay against the packaged fixture,
**not** genuine security behavior, secure authorship, or a real Kubernetes
observation. Existing output directories are never overwritten. See
[synthetic evidence limitations](docs/ENGINE_CLI.md).

**Validation is not authorization.** The real-environment `run`, `compare`, and `report`
commands currently refuse execution and return a nonzero exit status. The
sample RBAC profile is schema data only; it does not provision VMs or Kubernetes,
connect to Cloudflare, or grant approval to run a workload. This package is
*not installed on the VPS by the existing Ansible playbook*. See
[contract CLI and limitations](docs/ENGINE_CLI.md).

## Pinned K3s VM design — SC-12 (offline only)

The new `slipcage plan-vm` command validates a non-executable,
version-pinned **design** and estimates the resources for one sequential
K3s VM from strictly operator-reported host figures. Its included fixtures
contain fake digests and are **not deployable images or a real VPS capacity
measurement**:

~~~bash
slipcage plan-vm examples/vm-plans/k3s-synthetic-design.json \
  --inventory examples/vm-plans/host-capacity-synthetic.json --json
~~~

The output always states that artifact verification, KVM/guest boot, network
isolation and execution authorization have **not** happened. This change
does not enable a real `run` or VM-provisioning command. See
[SC-12 pinned VM feasibility](docs/K3S_VM_FEASIBILITY.md).

## VM lifecycle controller simulation — SC-13a

The in-memory VM state machine models bounded admission, startup, timeout,
cancellation, teardown and strict sequential baseline/candidate gating:

~~~bash
slipcage simulate-vm-lifecycle examples/vm-plans/k3s-synthetic-design.json --scenario timeout --json
slipcage simulate-vm-pair examples/vm-plans/k3s-synthetic-design.json --baseline-scenario success --candidate-scenario success --json
~~~

**These commands do not run QEMU, allocate disks, contact Kubernetes, or
modify the host.** The output always says real VM boot, execution authorization,
host changes and real cleanup verification are false. Live SC-13 VM execution
remains blocked on separately approved real image provenance, VPS measurements,
provider permission and process/network isolation; see
[SC-13 VM lifecycle design](docs/VM_LIFECYCLE_DESIGN.md).

## SC-13b1 — Private local VM asset byte checking (not a guest runner)

The new `slipcage verify-vm-artifacts` command performs bounded, read-only
SHA-256 checks over five fixed private files supplied by the operator and
compares them to the SC-12 plan's declared pins:

~~~bash
slipcage verify-vm-artifacts /path/to/operator-plan.json \
  --directory /path/to/private-assets --json
~~~

It **rejects the repository's synthetic example plan**; it requires a
non-synthetic, but still *untrusted*, operator-supplied declaration. Matching
byte hashes do not authenticate software origin, inspect image/archive
contents, check provider authorization or start any QEMU guest. Outputs always
record `execution_authorized: false`, `vm_launched: false` and
`software_origin_authenticated: false`. This is a development-time check
only; Ansible does not install it on the VPS. See
[SC-13b1 limits and live VM prerequisites](docs/VM_ASSET_PREFLIGHT.md).

## SC-13b2 — Offline signed-statement and host snapshot checks

Two read-only commands add prerequisites for any future disposable VM:

~~~bash
slipcage verify-vm-provenance /private/operator-plan.json --statement /private/statement.json --signature /private/statement.sig --public-key /private/trusted-key.raw --json
slipcage assess-vm-host /private/operator-plan.json --snapshot /private/host-snapshot.json --json
~~~

The first verifies an Ed25519 signature *against a supplied raw public key* bound to all five asset digests and the plan. **Publisher key identity must be trusted independently**; the command cannot establish that trust, revocation, or upstream release authenticity. The second checks the operator's declared host headroom and KVM/cgroup flags **without accessing the VPS**, and cannot establish actual measured host readiness. Both commands always report execution_authorized=false and vm_launched=false. See [SC-13b2 trust and host gates](docs/VM_PROVENANCE_HOST_GATE.md).

## SC-13b3 — Explicit read-only Linux host observation

SC-13b3 provides a **manual, operator-invoked** `slipcage inspect-vm-host`
command. It reads bounded Linux memory, visible CPU count, nominated scratch
filesystem free space/inodes, and KVM-character-device/cgroup-v2 *presence*:

~~~bash
slipcage inspect-vm-host /path/to/operator-plan.json \
  --scratch-root /path/to/existing-approved-scratch-directory --json
~~~

**Do not run this on the VPS until separately authorized.** No operator
commands are executed by CI; unit tests use injected synthetic data and
mocked host counters. The tool never boots guests, opens /dev/kvm, connects
to the network, creates disks or changes host settings. Even a numerically
favorable observation reports provider permission, KVM usability, cgroup
quotas, active guest safety and execution authorization as **unverified/false**.
See [SC-13b3 limitations and operator review](docs/VM_HOST_OBSERVATION.md).

## SC-13b4 — Incomplete QEMU launch blueprint (offline only)

The `slipcage plan-qemu` command produces a fixed, **paused and incomplete**
QEMU argument prefix from a validated, nonsynthetic SC-12 plan and checked
local asset bytes. It **does not start QEMU**, attach disks/kernels/NICs,
create an overlay or enforce any host process limits:

~~~bash
slipcage plan-qemu /path/to/operator-plan.json \
  --assets-dir /path/to/operator-private-assets --json
~~~

Its output always marks `argv_is_complete_launch_command: false`,
`execution_authorized: false`, `real_vm_launched: false` and host/runtime
verification false. The CLI rehashes supplied private assets, but actual
software publisher identity, host KVM and provider approval remain unverified.
**Do not manually execute the displayed prefix**. The real launch library
unconditionally refuses. See [SC-13b4 incomplete blueprint](docs/QEMU_BLUEPRINT.md)
and open runtime prerequisites under Issues #23 and #25.

## SC-13b5 — Offline supervisor budgets and crash fencing

The new `slipcage simulate-vm-supervision` and
`slipcage simulate-vm-supervision-pair` commands exercise a pure in-memory
resource/deadline and single-owner lease model using a nonsynthetic SC-12 plan
and read-only local asset checks:

~~~bash
slipcage simulate-vm-supervision /path/to/development-plan.json \
  --assets-dir /path/to/private-assets --scenario cleanup_failure --json
~~~

The model rejects stale revisions, overlapping attempts, invalid state
transitions, deadline and simulated resource breaches. A crash or failed
cleanup **quarantines** the simulated attempt and blocks subsequent attempts
without automatic clearance. The budget and journal are **not backed by
systemd, cgroups, disk quotas, process watchdogs or persistent OS locks**.
No guest is started and no disk is written. See
[SC-13b5 lifecycle supervision contract](docs/VM_SUPERVISION_CONTRACT.md).

## SC-13b6 — Private local VM staging and quarantine (no guest)

The new `stage-vm-reservation` CLI makes a tiny **permanent, append-only
reservation record** in one existing private development root, and
`inspect-vm-reservation` can validate it read-only. Optional
`quarantine-vm-reservation` appends a non-clearable review marker:

~~~bash
slipcage stage-vm-reservation /private/operator-plan.json \
  --assets-dir /private/operator-assets \
  --root /private/newly-approved-development-root --attempt baseline --json
slipcage inspect-vm-reservation /private/newly-approved-development-root --json
~~~

**Development-only local storage writes:** no overlay, guest, QEMU, systemd,
network or production VPS change. The fixed slot is never removed or reused,
including after incomplete/crashed publication. The staging marker is **not
a host-wide exclusive lease**, and no OS cgroup/watchdog/cleanup runs.
Do not use existing production data paths or run it on the VPS without
separate explicit approval. See
[SC-13b6 local reservation safety contract](docs/VM_PRIVATE_RESERVATION.md).

## SC-13b7 — Read-only QCOW2 base and overlay-intent preflight

The new `slipcage inspect-vm-backing` command checks a narrow **QCOW2 v3
header shape** and entire local base-image SHA-256 against nonsynthetic SC-12
operator-supplied pins. It also binds the check to a valid **non-quarantined**
SC-13b6 private staging reservation:

~~~bash
slipcage inspect-vm-backing /private/operator-plan.json \
  --assets-dir /private/operator-assets \
  --reservation-root /private/existing-staged-root --json
~~~

The base header must have **no embedded backing-file path, snapshots,
encryption or unsupported feature flags**. This does **not** inspect the full
QCOW2 allocation/refcount graph, authenticate upstream publishers, create an
overlay, traverse a backing chain or prove image immutability. No QEMU or
qemu-img commands run. See [SC-13b7 conservative base preflight](docs/VM_QCOW2_BASE_PREFLIGHT.md).

## SC-13b8 — Read-only overlay remnant and recovery assessment

`slipcage review-vm-overlay` examines the fixed private staging slot **without
opening or deleting any overlay**. It separates intact, incomplete, corrupt,
quarantined and unknown states and conservatively flags any unexpected
`overlay.qcow2` filesystem node for manual preservation:

~~~bash
slipcage review-vm-overlay /private/operator-controlled-reservation-root --json
~~~

All cases refuse automatic cleanup, overlay creation and VM execution. A valid
staging record with no observed overlay **does not** establish actual process
cleanup or permission to run a guest. CI only tests tiny disposable fixtures;
no QEMU/guest workloads or VPS paths are accessed. See
[SC-13b8 recovery triage limitations](docs/VM_OVERLAY_RECOVERY_REVIEW.md).

## SC-13b9 — Kernel advisory lock around local recovery inspection

The optional `slipcage review-vm-overlay-locked` command acquires a real,
**same-root Linux advisory flock** for the duration of SC-13b8's read-only
recovery scan. It may create one **empty 0600 persistent lockfile** in the
operator-chosen preexisting private scratch root:

~~~bash
slipcage review-vm-overlay-locked /private/development-reservation-root --json
~~~

This is **not** a guest-process or host-global lease: the lock is released
before the command returns, and process death cannot prove guest cleanup.
A safe-looking observation cannot authorize QEMU or deletion. CI checks real
cross-process flock contention using ephemeral scratch roots only; no
production VPS files, overlays or VMs are touched. See
[SC-13b9 scoped local review lock](docs/VM_LOCAL_REVIEW_LOCK.md).

## SC-13b10 — Durable offline identity and monotonic fencing generations

The development-only `stage-offline-vm-generation`,
`inspect-offline-vm-generations` and `resolve-offline-vm-generation`
commands persist **hash-linked, numbered offline intent records** under a
separate pre-existing private local root. They serialize cooperating writes
with a scoped Linux advisory lock, reject stale expected generations,
preserve interrupted records, and block unresolved/quarantined identities.

**No host-wide guest lease, process lifetime lock, VM, disk or cleanup is
implemented.** Even an `offline_intent_abandoned_not_vm_cleanup` resolution
is **not proof of guest cleanup or authorization for live execution**.
Only tiny files in intentionally selected development roots are created.
See [SC-13b10 offline fencing journal](docs/VM_OFFLINE_FENCING_JOURNAL.md).

## Development and testing

Use PRs from feature branches; do not merge or release without the project owner's review. Local baseline validation matches the repository's CI entry point:

~~~bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q app scripts src tests
bash -n scripts/*.sh
ansible-playbook -i inventory/hosts.ini.example playbooks/site.yml --syntax-check
~~~

The GitHub workflow also validates YAML and builds benign guest initramfs files without booting guests. Read [development workflow](docs/DEVELOPMENT_WORKFLOW.md) for ownership, release gates, evidence requirements, hotfixes and proposed GitHub settings. See the [PR template](.github/PULL_REQUEST_TEMPLATE.md) for reviewer checks.

## Documentation

**Product and development**

- [Vision and v1 boundaries](docs/PRODUCT_VISION.md)
- [Current/target architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Experiment contracts and result semantics — proposal only](docs/EXPERIMENT_CONTRACT.md)
- [Milestone roadmap to v1.0](docs/V1_ROADMAP.md)
- [Human-approved development and deployment workflow](docs/DEVELOPMENT_WORKFLOW.md)
- [Security rules](SECURITY.md)

**Existing v0.x operational documents** (historical release-specific procedures; consult deployed SHA before use)

- [Research intelligence](docs/RESEARCH_INTELLIGENCE.md), [recovery](docs/RECOVERY.md) and [backup](docs/BACKUPS.md)
- [Environment readiness](docs/ENVIRONMENT_READINESS.md), [guest lifecycle](docs/GUEST_LIFECYCLE.md) and [controlled benign experiments](docs/CONTROLLED_EXPERIMENTS.md)
- [Evidence observability](docs/EXPERIMENT_OBSERVABILITY.md) and [controlled synthetic fault drills](docs/CONTROLLED_FAILURE_RECOVERY.md)
- [Operational reliability](docs/OPERATIONAL_RELIABILITY.md), [operational assurance](docs/OPERATIONAL_ASSURANCE.md) and [incident runbooks](docs/INCIDENT_RUNBOOKS.md)

The historical operational documents retain version-specific language; they are not the authoritative v1 product roadmap.

## Safety and availability

Guest experiments and higher-risk workloads are **not** started automatically by a repository update. No default-off webhook, off-server backup destination or experimental execution profile should be enabled without a separately reviewed and approved change. Encrypted off-server backups remain deferred. Current VPS capacity and permissions must be checked before trying a new K3s environment. Neither advisory data nor user-supplied experiment parameters may be interpreted as shell instructions.

Slipcage's initial commercial product is approved, non-destructive security regression testing. Broader container-runtime research, patch reproduction and hypervisor security experimentation are longer-term, separately authorized tracks.
