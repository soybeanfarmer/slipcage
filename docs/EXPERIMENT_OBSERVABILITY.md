# Slipcage v0.7 — experiment observability and safety

v0.7 adds **manual, read-only** analysis of private disposable guest-run
records. No new guest workloads, Dagu integrations, automatic timers,
fuzzing, network scans, VM-escape tests, or security-boundary experiments.

## What changes

Every newly started benign boot/experiment series writes a private
`run.json` **before any guest starts**. It records the chosen fixed
profile, cycle count, host kernel release and SHA-256 fingerprints of the
locally available controller, guest probe, distro kernel copy and static
initramfs. A missing fingerprint is recorded as null, not success.
These are not signed attestations; local file writes can be changed by
someone with the same account permissions.

Each cycle now also has a precise failure_category such as
outer_timeout_process_group_killed, qemu_error,
known_answer_mismatch, resource_evidence_missing_or_invalid,
missing_structured_probe_result or unexpected_guest_configuration.
No arbitrary guest arguments or new code paths are introduced.

The audit cross-checks:
- complete runs and the summary's reported counts;
- each saved cycle-NN.json against the final summary;
- presence of the corresponding bounded cycle-NN.log file;
- experiment known-answer flags and finite nonnegative resource readings;
- manifest version and profile, when present (v0.6 legacy runs are valid
  without run.json);
- SHA-256 fingerprints of stored JSON/log artifacts, limited to private
  files no larger than 64 KiB.

An audit distinguishes completed success, completed failure, inconsistent
evidence, interrupted/incomplete artifacts, and possibly active runs.
If the lifecycle flock lock is held, an unfinished run is **not** claimed
to be abandoned. Audits do not clean up, delete, resume, mutate,
replay or re-run any guest workload.

## Operator procedure (after explicitly approved v0.7 release)

Check the VPS deployed the release, then use the manual read-only audit:

    sudo systemctl start slipcage-pull-deploy.service
    sudo cat /var/lib/slipcage/deployed-sha
    sudo systemctl start slipcage-experiment-audit.service
    sudo journalctl -u slipcage-experiment-audit.service -n 60 --no-pager -l

That unit runs as slipcage-vmprobe, with the guest evidence directory
read-only, no /dev/kvm access, no network, no root capabilities and a
128 MiB memory cap. It outputs a concise Markdown report to the journal.

For machine-readable JSON or a one-run summary, use the same read-only tool
via the original unprivileged account:

    sudo -u slipcage-vmprobe python3 /usr/local/lib/slipcage/experiment-audit.py --limit 1 --format json

The command exits 0 only when selected runs are complete successes; it
exits 1 if any run failed or evidence is inconsistent/incomplete and 2
if there are no runs, an inaccessible source, or invalid arguments.
The journal still contains the report if systemd marks a failed audit.

**Pre-existing v0.6 run directories are supported** even though they
lack run.json, and their existing final reports are not modified.

## Read-only systemd quota configuration validation

The new limits-check.py **does not start a VM or allocate guest resources**.
It queries the configured systemd values for four allowlisted
guest-unit instances and flags missing, oversized or unexpectedly
permissive quotas and device exceptions. For instance:

    python3 /usr/local/lib/slipcage/limits-check.py --unit slipcage-experiment@1.service

It checks the configured user, PrivateNetwork, ProtectSystem,
NoNewPrivileges, DevicePolicy/DeviceAllow, MemoryMax <= 1280 MiB,
CPUQuota <= 100%, TasksMax <= 64, and control-group cleanup.
Run it after deployment; systemd property serialization can vary by
systemd version, so a false/unknown result should prompt inspection with:

    systemctl show slipcage-experiment@1.service -p MemoryMax -p CPUQuotaPerSecUSec -p TasksMax -p DeviceAllow

**Important:** This confirms configuration, NOT whether cgroup limits
actually trigger correctly under stress, nor whether the guest is
secure against hostile code. Do not remove limits or run intentional
stress tests against the shared VPS.

## Controlled offline fault checks

CI uses fake, tiny local subprocesses and constructed artifact trees
rather than running QEMU. Regression tests cover:
- an outer timeout killing the probe's **process group**;
- invalid results and resource evidence failing closed;
- an interrupted series whose final summary is missing;
- detection of modified, missing or symlinked evidence;
- the ongoing lifecycle flock preventing false "abandoned" claims;
- strict systemd policy inspection with mocked outputs.

This protects against regression in the decision logic; it is not
an on-host forced failure drill. An on-host, controlled interruption
of a harmless guest should be separately reviewed and permitted
before testing actual cgroup enforcement or crash recovery.

## Retention and backup boundary

The prior bounded 20-complete-run retention policy continues. Incomplete
runs are preserved; the read-only audit does not delete them. This
is useful for diagnostics but means interrupted runs may accumulate:
review disk usage and require human approval for later cleanup.

Your local SQLite/report backup schedule remains unchanged; the
disposable guest logs are **not backed up** by it. Per your request,
encrypted off-server backups are not being configured at this stage.
Do not use this facility for irreplaceable security findings or
valuable private corpora until artifact retention and backup coverage
are separately designed.
