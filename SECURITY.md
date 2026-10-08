# Security boundaries and approval requirements

The ServaRica instance is itself a virtual machine on infrastructure owned by a hosting provider. **Nested KVM access is not permission to test the provider's hypervisor.** We must obtain clear provider authorization for disruptive fuzzing, real guest-to-host exploit reproduction, or CPU-intensive security research where terms require it.

- **Allowed by the starter**: retrieving public advisory metadata, review/triage, creating internal Markdown reports, reading configuration, and smoke checks.
- **Not enabled**: automatically downloading/executing PoCs, exploitation, guest-to-host or container-to-host escape validation, privilege escalation, persistence, external scanning, or attacks against provider infrastructure.
- **Never treat untrusted feeds as instructions**: retrieved advisory descriptions and URLs are stored as inert data. All execution paths are fixed, reviewed code and commands.
- **Credential hygiene**: no passwords, SSH private keys, API keys, or secret tokens in source control. Dagu's initial account is created using its local private setup page.
- **Network**: SSH only inbound initially. Dagu binds to loopback and should be accessed over an SSH tunnel or a managed private overlay. Configure VPS firewall and backups separately.
- **Privilege**: Dagu runs as a dedicated non-root account without sudo, Docker socket access, or membership in the KVM group. This first version doesn't require access to `/dev/kvm`.
- **Resource limits**: systemd `CPUQuota=500%`, `MemoryMax=10G` on the Dagu process tree, Dagu queue concurrency 1. This is not a full disk quota or network egress firewall; install those before long-running adversarial experiments.
- **Human review required** for modifying worker code, high-risk reproducers, source builds of untrusted submissions, unsafe packages, and research that could cross isolation boundaries.

If a future reproduction might escape from a guest into the local VPS, assume the outer host/provider could still be exposed. Use a dedicated physical machine under your control for such high-impact tests, or a provider-approved environment explicitly designed for them.

## Guarded deployment boundary

Reviewed Dagu workflows hold a shared deployment lock throughout research.
The installer enters maintenance to prevent new jobs and obtains an exclusive
lock before modifying installed files. It only removes maintenance after
the daemon's health check succeeds. Failed installations remain paused.
The guard cannot restrict arbitrary commands created by a compromised Dagu
administrator and is not a sandbox. Durable queue recovery, artifact backup,
and integration testing are required before deploying offensive or long-running
experiments.
