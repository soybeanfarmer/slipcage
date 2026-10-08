# Slipcage v0.5 — Safe disposable guest lifecycle testing

This release adds an explicitly **manual**, bounded Linux microguest
reliability check. It repeats the *existing* benign v0.4.1 boot, with its
fixed Ubuntu kernel and locally built BusyBox initramfs. This is not a
fuzzer, guest attack harness, malicious-code sandbox, or hypervisor test.

## Scope and safeguards

- No Dagu workflow changes, guest automation timer, scan, PoC or exploitation.
- No guest network, virtual disk, host-directory share, downloaded image,
  or untrusted code. No user-supplied QEMU arguments or shell execution.
- Runs as locked-down slipcage-vmprobe in a manually started systemd
  template service, with PrivateNetwork=yes, /dev/kvm-only device access,
  no capabilities, a read-only host root, 1280 MiB host memory cap,
  100% CPUQuota, and at most 64 tasks.
- Guest itself uses **one vCPU, 384 MiB RAM**, no networking, and no disk.
- Only **1–5 sequential cycles** per service invocation, one live guest
  per run. A failed cycle stops the series.
- Each inner boot has a 75-second QEMU timeout. The supervisor also gives
  the child process group an 85-second outer deadline, then kills the whole
  group if it hangs. The systemd start timeout is nine minutes and its
  default control-group kill behavior remains enabled.
- A rootless per-run flock prevents concurrent template instances.
- Only a result with guest_booted=true, exit_code=0, network=disabled and
  persistent_guest_disk=false counts as a success.
- Per-cycle JSON and bounded console excerpts are saved under
  /var/lib/slipcage-guest/runs/ in directories mode 0700, files mode
  0600. The latest **20 complete** run directories are retained.
  An interrupted, incomplete directory remains for inspection rather
  than being silently removed.

This is a benign smoke/reliability test only. Passing five boot cycles
does NOT establish hypervisor isolation, provider authorization for
fuzzing, resistance to VM escapes, or long-term stability.

## Manually run the test after releasing v0.5.0

Once the manually approved release has deployed, check the new unit:

    sudo systemctl cat slipcage-guest-cycles@.service
    sudo cat /var/lib/slipcage/deployed-sha

Assuming your hosting plan permits these bounded benign nested guests,
start with **one** cycle:

    sudo systemctl start slipcage-guest-cycles@1.service
    sudo journalctl -u slipcage-guest-cycles@1.service -n 30 --no-pager -l

Look for passed=true, requested_cycles=1, completed_cycles=1,
successful_cycles=1, and an absolute run_dir path. If it fails, stop
and inspect the reported reason rather than immediately retrying.

For a repeatability check, only after a single cycle passes:

    sudo systemctl start slipcage-guest-cycles@5.service
    sudo journalctl -u slipcage-guest-cycles@5.service -n 30 --no-pager -l

Inspect artifacts (root-owned discovery of filenames; rootless worker
owns the private logs):

    sudo find /var/lib/slipcage-guest/runs -maxdepth 2 -type f -name 'summary.json' -print
    sudo ls -lah /var/lib/slipcage-guest/runs

Use the reported run_dir from each service journal entry to inspect its
summary.json, cycle-NN.json and cycle-NN.log. JSON has durations and
success/timeout/failure information. Logs contain bounded console
excerpts, not full QEMU traces or reproducible vulnerability artifacts.

There is **no scheduled burn-in**. Each run requires an explicit
operator action. No changes to firewall/network access are required.

## Backup boundary

You chose to defer encrypted off-server backups, so v0.5 does not enable
or configure the optional Restic timer. Daily local SQLite/report backups
continue unchanged. They do **not** include these benign guest-cycle
logs under /var/lib/slipcage-guest. This is acceptable for disposable
readiness checks, but **not** suitable for unique crash corpora or
unpublished findings. Before such experiments, extend artifact backup
coverage and evaluate independent off-server encryption and restores.

## Future gates before fuzzing

Provider terms and workload authorization must be checked explicitly;
isolate guests from shared-host infrastructure; implement independent
artifact retention and rollback; inspect KVM reliability under realistic
but benign load; and verify the absence of guest-to-host shares. Do not
enable live fuzzing merely because these smoke tests pass.
