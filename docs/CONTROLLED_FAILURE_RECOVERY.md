# Slipcage v0.8 — Controlled Failure Recovery

This milestone checks failure and cleanup paths **without running a VM
or intentionally exhausting the VPS**. It is manual-only: no Dagu job,
timer, recurring load, or background test. Existing metadata research
and daily local backups remain unchanged. Encrypted offsite backups
remain deferred.

## Three bounded, non-VM drills

The new slipcage-fault-drill@.service runs as slipcage-vmprobe but
has **no /dev/kvm access**. It has private networking and devices,
a strict host filesystem, a 128 MiB memory cap, a 25% CPU quota,
a 32-task cap, a 40-second service startup limit and cgroup cleanup.

Only three fixed, reviewed Python actions are available:

1. **timeout**: launches one harmless sleeping local Python process
   and its sleeping child. After about a second it kills the new
   process group. A pass requires both parent termination and
   confirmation that the child has stopped executing, using Linux
   PID and process-start identity.
2. **report**: deliberately interrupts a synthetic private fixture
   writer before atomic publication. The existing read-only
   experiment audit must classify that fixture as
   interrupted_or_incomplete. No real run, SQLite DB or report
   is modified.
3. **limits**: reads the *actual running service's* kernel cgroup v2
   memory.max, cpu.max and pids.max files and checks they are finite
   and at most 128 MiB, 25% of a CPU, and 32 tasks. This does
   **not** deliberately exhaust CPU, memory or process quota.

There is no QEMU, guest disk, network, scanned target, user-supplied
command or malicious input. The optional all mode runs these three
checks in sequence and stops on the first failure. A separate flock
prevents simultaneous drills. Results and synthetic fixtures are
isolated under /var/lib/slipcage-fault, not the real
/var/lib/slipcage-guest evidence directory.

## Manual on-server checks after a reviewed v0.8.0 release

First verify the installed release, then start only the short,
harmless timeout drill:

    sudo systemctl start slipcage-pull-deploy.service
    sudo cat /var/lib/slipcage/deployed-sha
    sudo systemctl start slipcage-fault-drill@timeout.service
    sudo journalctl -u slipcage-fault-drill@timeout.service -n 30 --no-pager -l

Success requires passed=true, timeout_exercised=true,
worker_killed=true and child_no_longer_running=true.

Next test interrupting a *synthetic* private report, not a real one:

    sudo systemctl start slipcage-fault-drill@report.service
    sudo journalctl -u slipcage-fault-drill@report.service -n 30 --no-pager -l

Expected: passed=true, final_report_not_published=true,
writer_killed=true and audit_classification=interrupted_or_incomplete.

Finally inspect effective kernel resource restrictions:

    sudo systemctl start slipcage-fault-drill@limits.service
    sudo journalctl -u slipcage-fault-drill@limits.service -n 30 --no-pager -l

Expected: passed=true, memory_max_bytes at most 134217728,
cpu_quota_fraction at most 0.25 and pids_max at most 32. If cgroup v2
is unavailable or the systemd service has different limits, this
check fails closed. Do not relax resource policies to make it pass.

Only after those pass, the optional combined check is:

    sudo systemctl start slipcage-fault-drill@all.service

There is no timer or scheduled drill. Failures have private JSON
diagnostics in the reported run_dir. Investigate them rather than
repeating the drill in a loop. The synthetic drill results are
disposable and are not covered by local daily DB/report backups.

## What validation does and does not prove

CI uses real local sleeper processes for timeout handling, synthetic
interrupted report fixtures and fake cgroup files for policy tests.
CI never launches QEMU and checks the systemd service remains manual,
nonroot, guest-free, networkless and resource-limited.

On-server success provides evidence for these **specific** controlled
failure scenarios and for effective cgroup v2 configuration visible
to the process. It does not prove recovery from a real VPS reboot,
memory pressure/OOM behavior, arbitrary process cleanup, hypervisor
security isolation, or provider permission for intensive fuzzing.
Those remain separate reviewed and authorized milestones.
