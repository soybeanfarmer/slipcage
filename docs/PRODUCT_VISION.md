# Product vision and v1 boundary

**Slipcage — Know what broke before you upgrade.**

## Mission

Help security researchers, platform engineers and infrastructure teams answer **"When infrastructure changes, does its security behavior change too?"** Slipcage should make security boundary behavior measurable, reproducible and verifiable through controlled experiments.

The existing Slipcage repository originated as a guarded infrastructure security research lab. The transition to a security regression platform is incremental: retain proven operations and benign VM primitives while building a portable experiment engine, then a Kubernetes adapter, then a hosted product.

## Core user journey (target, not implemented yet)

1. Choose a **reviewed** security experiment and pin its version.
2. Configure a baseline and candidate version/configuration of an isolated infrastructure environment.
3. Obtain authorization and apply explicit workload/resource policy.
4. Provision disposable environments with recorded image, runtime and configuration provenance.
5. Execute identical normalized assertions (or document why an environment is incompatible).
6. Compare observed security behavior without conflating experiment failure, infrastructure error and security regression.
7. Retrieve structured, integrity-checked evidence and a human-readable report.
8. Independently re-run the pinned inputs, subject to external environmental and temporal limitations.

The initial launch focuses on Kubernetes RBAC, Pod Security Admission and NetworkPolicy behavior. K3s running in dedicated disposable QEMU/KVM VMs is the preferred early research target, conditioned on host capability, provider permissions, isolation review and acceptable resource use.

## Differentiation

- **Reproducibility:** pinned inputs, versioned experiment schemas, deterministic normalization and evidence preservation.
- **Differential testing:** compare baseline/candidate outcomes rather than providing a static vulnerability list.
- **Isolation and authorization:** disposable environments, reviewed non-destructive profiles, per-run budgets and auditable decisions.
- **Research extensibility:** versioned, reviewed test packs and worker adapter interfaces.
- **Automation:** remove repeated setup/teardown and comparison work without granting arbitrary code execution.

Slipcage is **not** intended to be a general-purpose vulnerability scanner, Kubernetes operations dashboard, unattended exploit runner, or public penetration testing service.

## Users, editions and validation

Initial users: independent security researchers, Kubernetes maintainers, platform engineers and DevSecOps teams. Planned open-core model:

- **Community/self-hosted:** portable experiment specification, core runner, selected reviewed research packs.
- **Hosted control plane:** experiment orchestration, teams/projects, job coordination, results exploration and private evidence management.
- **Execution:** managed or customer-controlled workers that connect outbound, authenticate, enforce policy and isolate approved workloads.

Cloudflare Workers, D1 and R2 are preferred initial hosted technologies, not irreversible dependencies. Use versioned APIs/interfaces and allow a later switch to PostgreSQL or another provider. Validate demand with working prototypes and design partners before committing to a large public SaaS deployment.

## v1.0 definition

An authorized researcher can select a supported security experiment, configure isolated baseline and candidate environments, run the assertion safely, examine a correct differential result and export a reproducible evidence-backed report through a secure web interface. Multiple projects/users are supported with authorization, isolation, quotas, job recovery and private evidence access.

### Explicit v1 exclusions

- Arbitrary user-supplied scripts and unreviewed executable experiments in hosted shared workers.
- Unapproved exploit proof-of-concepts, destructive tests, fuzzing, VM escapes and attacks on hosting infrastructure.
- A large marketplace of unreviewed test packs.
- Mandatory operation of Slipcage's own control plane on Kubernetes.
- Automatic expensive multi-cloud execution, advanced billing and broad vulnerability reproduction.

These exclusions are safety and focus decisions, not claims that those research areas cannot be pursued in separately approved future environments.

## First product proof

A reviewed Kubernetes RBAC assertion must produce a **passing security boundary** in one disposable environment and a **failing security boundary** in another with an intentionally weakened RBAC rule. Capture exact identities, operations, responses, normalized outcomes and complete provenance. Repeat successfully and confirm bounded cleanup. The first proof may compare configurations at the same K3s version; later tests compare software versions using the same interface.

See [roadmap](V1_ROADMAP.md), [proposed contract](EXPERIMENT_CONTRACT.md), [architecture](ARCHITECTURE.md) and [safety policy](../SECURITY.md).
