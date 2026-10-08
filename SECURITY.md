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

## Future v1 platform security boundaries (planned, NOT currently deployed)

This existing policy continues to apply to the metadata lab and manual benign QEMU tests. The proposed Kubernetes regression platform adds, but does not replace, those protections.

- Control-plane API and authentication must be separated from experiment execution. Do not let web requests, advisory data or user-submitted YAML become arbitrary Dagu workflow commands, shell strings or unreviewed Python.
- Only reviewed, non-destructive experiment profiles are allowed in initial hosted execution. Validation and worker-side authorization both enforce profile, project, environment and resource bounds.
- A disposable dedicated VM per test environment is preferred for initial Kubernetes tests. K3s introduces disk and network requirements that need a separately approved isolation design and provider-compliant validation before first execution.
- Every user/project access path must enforce tenant authorization, including job claims, API reads, evidence retrieval and deletion. Cloudflare Access by itself only gates the initial private beta.
- Durable worker leases require fencing and cleanup reconciliation. A lost lease is not permission to run two mutable attempts concurrently.
- Evidence must be private, bounded, sanitized and integrity-checked, and missing/inconsistent evidence must not yield a false security-regression claim. A SHA-256 digest alone is not a signature.
- Multi-tenant launch requires verified worker isolation, quotas, negative authorization tests, privacy/retention policy, independent recovery capability and operator-approved failure drills.
- Encrypted off-server backup service **remains disabled** unless separately authorized and tested; future production readiness does not implicitly authorize enabling it today.

See [current and target architecture](docs/ARCHITECTURE.md), [experiment contract](docs/EXPERIMENT_CONTRACT.md), [development approval process](docs/DEVELOPMENT_WORKFLOW.md), and [milestones](docs/V1_ROADMAP.md).
