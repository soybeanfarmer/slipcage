# Slipcage v0.6 — fixed, benign guest experiments

Slipcage v0.6 adds one **reviewed, packaged and deterministic** Linux workload
inside the disposable nested-KVM guest. This is a *manual reliability and
measurement check*, not fuzzing, vulnerability reproduction, hypervisor
escape research, or security testing against the hosting provider.

## Fixed in-guest work (no input or network)

The new /init script in experiment-v1.cpio.gz performs:

1. Sum integers from 1 through 1,000 (must equal 500500).
2. Sum their squares (must equal 333833500).
3. Compute SHA-256 of ASCII 'abc' (no newline) and compare with the
   well-known SHA-256 test vector.
4. Print **four exact known-answer console lines** and immediately power
   off the guest. Any error omits required success evidence.

The archive is built exclusively from Ubuntu busybox-static, a fixed
/init and /dev/console. Nothing is fetched at run time. The installed
Ubuntu kernel is staged read-only under /usr/local/lib/slipcage as in v0.4.1.

The host's manual-only entry point launches QEMU with **KVM, one virtual
CPU, 384 MiB guest RAM, no guest network, no drives, no file shares**. No
advisory contents, command-line payloads or scripts can be injected into
this test. A host verifier requires all four exact console markers plus
QEMU exit status zero; it does not accept a bare "OK" string.

## Resource measurements and limits

Each cycle's structured JSON records:

- wall_seconds: QEMU subprocess wall time.
- cpu_user_seconds and cpu_system_seconds: Linux resource usage
  for the QEMU child (not CPU usage of the entire VPS).
- qemu_peak_rss_kib: Linux ru_maxrss, the peak resident memory
  reported for the child QEMU process, in KiB. It is **not** the guest
  memory allocation or the overall cgroup peak.
- seconds: outer lifecycle supervisor duration and exit status.
- known_answers_verified, passed, and a failure reason.

The service remains unprivileged (slipcage-vmprobe) and systemd-isolated
with a 1280 MiB host cgroup limit, CPUQuota=100%, TasksMax=64,
PrivateNetwork=yes, ProtectSystem=strict, and only /dev/kvm device
access. The inner QEMU timeout is 75 seconds, outer process-group timeout
85 seconds, and the systemd oneshot timeout is 5 minutes. A timeout
terminates the process group, not merely the Python controller.

The tested v0.5 per-cycle private report/console storage and flock
serialization are reused. There is a **shared 20-complete-run retention
cap** under /var/lib/slipcage-guest/runs across benign boot and experiment
runs. An incomplete interrupted run is preserved for inspection.

## Manual on-VPS checks, after reviewed v0.6.0 release

Verify the release deployed successfully:

    sudo systemctl start slipcage-pull-deploy.service
    sudo cat /var/lib/slipcage/deployed-sha
    sudo systemctl is-active isolab-dagu.service

Only if your hosting plan permits this benign nested guest test, run **one**
experiment:

    sudo systemctl start slipcage-experiment@1.service
    sudo journalctl -u slipcage-experiment@1.service -n 30 --no-pager -l

A passing JSON summary must contain mode: fixed_arithmetic_sha256_v1,
passed: true, requested_cycles: 1, successful_cycles: 1, and the
resource measurements for that cycle. If it fails, preserve the logs and
stop. Do not disable timeouts, change KVM permissions or elevate QEMU.

After the one-cycle test passes, optionally check consistency with
**three sequential fixed guest experiments**:

    sudo systemctl start slipcage-experiment@3.service
    sudo journalctl -u slipcage-experiment@3.service -n 40 --no-pager -l

Other instance counts above three fail closed. No timer is installed or
enabled for experiment execution. Nothing changes in the existing Dagu
advisory intelligence workflows, production data or candidate queue.

The run_dir in the journal summary identifies private summary.json,
cycle-NN.json, and bounded cycle-NN.log files. Retrieve them with
normal root privileges and avoid publishing internal logs by default.

## Backups and future workload boundary

The existing daily local database/report backups are untouched. The user
has deferred encrypted off-server backup setup. These disposable readiness
artifacts are **not** included in existing backups. No unpublished security
findings or irreplaceable corpora should be stored here.

This check confirms only a small, known-safe guest workload's behavior and
measurement. It does **not** establish isolation against malicious guests,
permission for VM escape experiments, provider authorization for CPU-heavy
fuzzing, long-duration stability or hypervisor security. Those require
separate technical design and explicit authorization review.
