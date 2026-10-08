# Slipcage architecture: deployed v0.x and proposed v1.0

This document **distinguishes current repository implementations from intended capabilities**. It is a design reference, not a claim that future services are deployed.

## 1. Existing lab (implemented, runtime verification separately required)

~~~mermaid
flowchart TD
    A[GitHub Advisory and NVD metadata] --> B[Scheduled Dagu discover]
    B --> C[Python coordinator and SQLite]
    C --> D[Deduplicated advisory priorities]
    D --> E[Guarded single-worker review queue]
    E --> F[Metadata-only Markdown reports]
    G[SSH tunnel] --> H[Loopback-only Dagu dashboard]
    H --> B
    I[Manual operator action] --> J[systemd-bound QEMU/KVM microguest]
    J --> K[Fixed benign experiment and JSON/log evidence]
    L[GitHub reviewed release] --> M[VPS outbound pull deploy + Ansible drain guard]
    N[Local backups, restore assurance and health] --> C
~~~

The repo provides a pinned Dagu installation, Python metadata research, SQLite, guarded Ansible/systemd deployment, local backups, restore assurance, operational health and manual benign KVM experiments. It does **not** provide K3s clusters, generic experiment contracts, security assertions, baseline/candidate comparisons, distributed workers, a Cloudflare API or multi-tenant access. GitHub CI primarily exercises offline tests and guest-image construction; it does not prove live VM operation.

Current trust boundaries:

1. **Dagu:** loopback-only web UI, built-in admin authentication, non-root `isolab` service account; workflow editing is shell-equivalent within that account.
2. **Untrusted advisory data:** metadata is treated as inert input, not executable instructions. Reviewed worker commands use fixed arguments and guarded execution.
3. **Benign QEMU:** dedicated unprivileged `slipcage-vmprobe` user with device restrictions, no guest network/disk/share, hard timeouts and bounded quotas; permission to use nested KVM is provider-specific.
4. **Evidence:** private on-VPS directories with hashes and audits. Hashes detect content changes relative to a trusted recorded digest, but do not provide signed, remote, tamper-proof attestation.
5. **Operations:** explicit GitHub release promotion; outbound VPS pull, deployment drain guard, health checks and local restore checks. Same-VPS backups do not protect against VPS loss.

## 2. Intended product topology (NOT YET IMPLEMENTED)

~~~mermaid
flowchart TD
    R[Authorized researcher] --> UI[React / TypeScript dashboard]
    UI --> API[Authenticated Cloudflare Worker API]
    API --> DB[(D1 metadata: users, projects, runs)]
    API --> J[Durable job coordination / lease store]
    API --> ART[(Private R2 evidence)]
    W[Authenticated outbound Python worker] -->|claim, renew, submit| J
    W -->|verified artifact upload| ART
    W --> VM[Disposable QEMU/KVM VM]
    VM --> K3S[Dedicated K3s test cluster]
    K3S --> T[Reviewed assertion pack]
    T --> VM
~~~

**The control plane never executes experiment payloads.** Workers initiate outbound connections with revocable, scoped credentials. Worker-side policy validates the reviewed experiment profile, authorization, environment pins and quotas before allocating resources. The API must enforce project authorization independently of the web UI. Cloudflare Access can gate a private beta but is not sufficient as multi-tenant authorization.

### Logical components and interfaces

| Component | Responsibility | Contract boundary |
| --- | --- | --- |
| Experiment specification | Immutable, versioned description of assertions, inputs and budgets | Portable schema; rejects arbitrary commands |
| Research engine | Validation, execution adapters, normalization, evidence assembly and comparison | Python library and CLI; works without hosted API |
| Environment adapter | Create/pin/inspect/tear down an environment | Strict lifecycle, cleanup and budget guarantees |
| Assertion adapter | Execute reviewed allow/deny/isolation assertions | Typed observations with explicit error/skip states |
| Worker | Authenticate, claim, fence, execute, upload and report job completion | No inbound public worker port required |
| Control plane | Users, projects, approval, job metadata, schedules and result indexing | Tenant-scoped API and durable state transitions |
| Artifact store | Store private inputs, observations, manifests and reports | Authenticated access, digest verification, retention policy |

The engine must not assume that D1/R2/Cloudflare are always available; the community runner should function locally with filesystem evidence and suitable persistence.

## 3. Experiment lifecycle and outcome semantics

Proposed state transitions (to be implemented in separate milestones):

~~~text
created -> validated -> approved -> queued -> leased -> provisioning
  -> running -> collecting -> comparing -> completed
                                  \-> failed / inconclusive
leased/running -> cancel_requested -> cleanup -> cancelled
leased/running -> worker_lost -> reconciling -> retry_or_failed
~~~

Transitions must be durable and idempotent. A lease timeout does **not** automatically authorize duplicate concurrent execution: the worker must be fenced and the previous environment must be reconciled. Each job carries immutable experiment and environment digests and a project-scoped authorization decision. Terminal status is separate from assertion outcomes (e.g., an expected API denial is a security PASS).

Normalized results distinguish `PASS`, `FAIL`, `ERROR`, `SKIP`, and `INCONCLUSIVE`. Differential comparison distinguishes *changed observed security behavior* from *different infrastructure health or incompatible configurations*. See [contract proposal](EXPERIMENT_CONTRACT.md).

## 4. Isolation and safety model (required before hosted execution)

- **Approved jobs only:** v1 hosted workers execute reviewed, non-destructive packs; never execute user-controlled shell strings or arbitrary code from experiments, feeds or the control plane.
- **Authorization:** every execution is tied to a user, project, experiment pack version, environment and resource budget. The control plane and worker independently enforce relevant policy.
- **VM boundary:** use a fresh disposable VM per Kubernetes environment, with guest storage/image integrity controls, sanitized input and no host directory mounts, host credentials or docker socket.
- **Networking:** K3s needs networking inside its VM. Use an explicitly configured guest network and deny uncontrolled guest-to-management, peer-tenant, metadata-service and provider networks. NetworkPolicy experiments require known CNI support and connectivity controls, not assumptions.
- **Limits:** explicit CPU, memory, disk, task count, time, concurrency, network policy, disk exhaustion checks and terminal process-group/VM cleanup. Preserve failed evidence but enforce separate retention caps.
- **Worker trust:** treat workers as security-sensitive; use scoped, rotatable credentials, minimize egress privileges, validate artifact inputs and protect host management access.
- **Tenant boundary:** project isolation applies to API, run results, job state, worker dispatch and evidence retrieval. Signed/expiring URLs alone do not replace authorization.
- **Provider constraints:** a nested VM on a shared VPS is not authorization for escape attempts against the provider. Higher-risk research requires separately authorized and suitable infrastructure.
- **Failure handling:** crash during any transition must have a documented evidence and cleanup response. Avoid silent automatic deletion of incomplete or suspicious artifacts.

A nested K3s design needs separate feasibility work because the current benign guest is diskless and networkless. Begin with **sequential** baseline and candidate runs on the existing constrained VPS; enable concurrency only after measurements and review.

## 5. Reproducible evidence and comparison

Proposed minimum evidence bundle: versioned run manifest, experiment spec digest, reviewed pack digest, environment image/kernel/K3s digests, effective policy inputs, assertion identity and principal, raw but bounded protocol observations, normalized result, timings, tool/runtime versions, cleanup outcome, per-file hashes and generated comparison report.

- Input pinning and artifact checksums enable *replay and audit*; they do not imply that timing-dependent behavior is deterministic.
- Redact credentials and sensitive Kubernetes tokens before collection and storage. Avoid publishing raw kubeconfigs, node secrets or identifying tenant information.
- Compare equivalent assertions and explicitly report incomparable environment/protocol states. Do not label an unready cluster, request timeout or missing evidence as an observed security-policy regression.
- Evidence is private by default. Production-grade offsite backup/restore, key management, retention and deletion must be designed before multi-tenant launch.

## 6. Technology decisions and portability

| Initial preference | Purpose | Decision status |
| --- | --- | --- |
| Python | Portable engine, worker and evidence comparison | Reuse existing language |
| QEMU/KVM + K3s | Disposable Kubernetes environments | Planned; nested host capability must be proven |
| systemd + Dagu | Existing trusted operations | Keep; not exposed as arbitrary user job interface |
| React/TypeScript/Vite | Research dashboard | Planned |
| Cloudflare Workers + Access | Beta API and initial gate | Planned; add real tenant authorization |
| D1 | Hosted metadata | Planned; migration/versioning and portable storage interface required |
| R2 | Private artifact storage | Planned; authorization and integrity checks required |
| Worker leases / optionally Queues | Reliable delivery and fencing | Planned; semantics require real integration tests |
| Ansible + GitHub Actions | Deploy/CI with human approval | Existing; maintain production gate |

Revisit these choices based on measured requirements. Do **not** deploy Slipcage itself on Kubernetes merely to test Kubernetes.

### SC-12 — pinned VM plan is only a declaration

The proposed K3s VM design has a strict, offline-only JSON validation module
and a conservative **operator-reported** resource estimator. It does not
validate actual image hashes, open `/dev/kvm`, instantiate a QEMU process,
configure a bridge, boot K3s, or authorize workloads. Its sample data is
synthetic; genuine artifact pins and live capacity/permission proof remain
outstanding. See [SC-12 feasibility and safety gate](K3S_VM_FEASIBILITY.md).

## 7. Validation ladder

1. **Offline CI:** specification, assertion state, comparator and evidence fixtures; existing tests remain green.
2. **Manually approved VM:** benign QEMU boot, resource and cleanup behavior on permitted VPS; record deployed SHA and logs.
3. **Disposable K3s integration:** pinned cluster startup, admission/RBAC/NetworkPolicy tests, repeatability, negative controls and cleanup.
4. **Private hosted beta:** single authorized worker and tenant, then explicit multi-project isolation, quotas and fault-injection verification.
5. **v1 release:** design-partner use, independent reproduction, operations/runbooks, backup/restore and security qualification.

No ladder stage is proven by documentation or source-level CI alone. See [development workflow](DEVELOPMENT_WORKFLOW.md), [roadmap](V1_ROADMAP.md) and [security policy](../SECURITY.md).
