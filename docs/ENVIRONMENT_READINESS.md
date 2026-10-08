# Slipcage v0.4 — Research environment readiness

This release prepares **manual, benign nested-virtualization testing** and an
**opt-in** encrypted off-server backup workflow. It does **not** enable
fuzzing, known vulnerability reproductions, scans, exploitation or automated
guest creation. The existing Dagu research jobs and dashboard remain unchanged.

## Scope and provider authorization

The VPS provider advertises nested KVM, but /dev/kvm existing does NOT
prove nested guest execution. Confirm your plan/provider permits nested guests
and CPU-intensive testing before running more than the benign tests here.
Never attack or probe the hosting provider's hypervisor or other customers.
All new tests run only on **your rented guest VPS**.

No KVM test starts automatically during installation.

## Stage 1: Read-only capability inventory

After deployment, on the VPS run:

    /usr/bin/python3 /usr/local/lib/slipcage/kvm-probe.py

This shows /dev/kvm character device availability and whether the *calling
user* can open it. Running as slipadmin may show no access even when the
dedicated probe account has permission; that is expected. It is only an
inspection, not an actual VM test.

## Stage 2: Inert KVM initialization (manual)

    sudo systemctl start slipcage-kvm-probe.service
    sudo journalctl -u slipcage-kvm-probe.service -n 30 --no-pager

This launches QEMU as the new locked-down slipcage-vmprobe account. It
allocates 256 MiB guest RAM, one virtual CPU, no drives or network, and
starts the machine PAUSED. A QMP query must report both KVM present and
enabled. It terminates without executing a guest OS. A successful result
proves only KVM initialization, not boot/reliability.

It is isolated with PrivateNetwork=yes, device access restricted to
/dev/kvm, a strict read-only host filesystem, CPUQuota=100%, MemoryMax=768M,
TasksMax=64, and a short timeout.

## Stage 3: Disposable Linux microguest boot (manual)

Ubuntu's busybox-static package and the installed kernel are used to build
a tiny initramfs containing only a static shell and a minimal /init script.
No third-party guest images are downloaded. The guest is ephemeral:
- 384 MiB RAM, one vCPU, and KVM-only (no TCG fallback)
- no virtual disks, network interface, host directory shares or host mounts
- a fixed kernel command line; emits SLIPCAGE_MICROGUEST_OK and powers off
- same unprivileged sandbox as stage 2, with 1280M host cgroup memory
  limit and a hard runtime cutoff (QEMU 75 sec / systemd 95 sec)

Run **only after the provider's terms permit benign nested guests**:

    sudo systemctl start slipcage-kvm-boot.service
    sudo journalctl -u slipcage-kvm-boot.service -n 50 --no-pager

Success requires the marker **and** QEMU exit status zero. Kernel/guest
compatibility may prevent boot even when KVM itself works. No untrusted
code or exploit payloads are supplied by Slipcage. This is an initial
boot smoke test, not endurance/stress testing or proof of security isolation.

Both KVM units are manually started, with no timers, no DAG and no new
public service ports.

## Encrypted offsite backups (NOT enabled automatically)

Restic is installed with an optional systemd service and timer.
**Nothing is transmitted** unless an operator configures an independent
offsite storage destination, initializes an encrypted repository, tests
credentials and explicitly enables the timer. No VPN subscription is
required; Restic supports SFTP/SSH servers, HTTPS rest-server and supported
object storage backends. Such storage may have separate costs.

All credentials belong exclusively on the VPS, not in GitHub, Dagu workflow
parameters, a chat message or any public report.

Expected on-server configuration:

    /etc/slipcage/offsite.env            root:root 0600
    /etc/slipcage/offsite-passphrase     root:root 0600

Example ENVIRONMENT FILE ONLY (never commit values):

    RESTIC_REPOSITORY=sftp:backup-user@backup-host:/private/slipcage
    RESTIC_PASSWORD_FILE=/etc/slipcage/offsite-passphrase

For SFTP, configure the root SSH client to use a purpose-specific key
stored under /etc/slipcage, plus a host key explicitly verified and pinned
out of band. With ProtectHome=yes in the systemd service, do not rely on
/root/.ssh for SSH identity or host keys. Standard root-owned SSH config
under /etc/ssh/ssh_config.d can refer to the key and pinned known_hosts.
Use a storage account that cannot access the research VPS.

Once a destination is selected, set up its repository and credentials
directly via a root shell, verify the remote host identity, initialize
the restic repository manually, and test remote restore/verification.
Only then run:

    sudo systemctl start slipcage-offsite-backup.service
    sudo journalctl -u slipcage-offsite-backup.service -n 40 --no-pager

The runner only transfers the newest **locally verified, completed**
backup snapshot (not the live SQLite database), and refuses a snapshot
older than 36 hours. Restic encrypts before uploading. The local source
remains untouched.

After a verified end-to-end test, explicitly opt in:

    sudo systemctl enable --now slipcage-offsite-backup.timer
    sudo systemctl list-timers slipcage-offsite-backup.timer --no-pager

Its UTC schedule is around 05:15–05:45, after the local daily backup.
The v0.4 installer leaves this timer **disabled**. Offsite retention,
remote credentials/host-key rotation, availability alerts, and full
disaster-recovery restore drills are not automatically configured.
Do not assume offsite disaster recovery until a snapshot has been
restored using an independent machine or storage destination.

## Priorities before autonomous fuzzing

1. Confirm provider permission and pass manual nested guest boot checks.
2. Exercise repeated benign boot cycles and measure resource usage.
3. Configure encrypted offsite backups and test a real remote restore.
4. Define a disposable KVM guest image policy and snapshot/revert strategy
   with no host resources mounted inside guest workloads.
5. Keep privileged host access, Docker socket access, and attack payloads
   excluded until isolation boundaries and authorization are reviewed.

A successful KVM test alone is not a license to test VM escapes against
the hosting provider.
