# Slipcage roadmap: current lab to v1.0

**Planning document, not a claim of completed work.** Baseline: GitHub v0.10.0, with CI source-level validation; live VPS SHA and runtime evidence must be verified by the human operator. Version numbers below are proposed release checkpoints, not automatic promotion triggers.

The target is an approved non-destructive Kubernetes security regression testing platform with reproducible evidence, baseline/candidate comparison, portable self-hosted execution and a secure hosted interface for multiple users.

## Milestone statuses and gates

- **Planned:** written scope and acceptance criteria.
- **Implemented:** branch reviewed, CI passed, and change merged by the owner.
- **Released:** owner explicitly approved/published a release.
- **Production-validated:** VPS has expected release SHA and the owner supplied approved runtime logs/test evidence, reviewed against milestone-specific expectations.
- For **documentation-only** work, completion may be a review of documentation and source checks; it never implies that a VM/integration was tested.

An issue should be independently testable and usually implemented by one focused PR; split large/uncertain entries into design spikes and smaller PRs. No automatic merge, release, SSH session or VPS service invocation by the implementation agent. See [workflow](DEVELOPMENT_WORKFLOW.md).

## Phase 0 — Align and preserve the foundation (proposed v0.11)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-01 | Verify deployed v0.10 baseline | Owner provides exact VPS SHA and approved smoke/health/restore evidence; record any deviation |
| SC-02 | Align product documentation | README, vision and architecture distinguish implemented lab and planned regression product |
| SC-03 | Set repository governance | PR template/workflow documented; owner enables supported GitHub branch/tag policies and verifies settings |
| SC-04 | Define initial boundaries/contracts | Document versioned experiment, worker and evidence interfaces plus threat model; no new execution |

Phase gate: foundation is documented and verified, safety remains unchanged, and any missing owner-only governance actions are tracked rather than claimed complete.

## Phase 1 — Reproducible experiment engine (proposed v0.12)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-05 | Installable Python engine/CLI | `validate`, `run`, `compare`, `report` surface with no live VM requirement |
| SC-06 | Versioned experiment spec | Schema rejects unknown profiles/unsafe inputs and supports fixtures |
| SC-07 | Typed assertion results | PASS/FAIL/ERROR/SKIP/INCONCLUSIVE distinguish security observations from infrastructure errors |
| SC-08 | Local fixture executor and adapters | Bounded execution and failure/timeout/cancellation tests |
| SC-09 | Canonical evidence bundles | Private manifests, provenance, checksums and corrupt-evidence refusal |
| SC-10 | Differential comparator | Known regressions/improvements; errors become incomparable |
| SC-11 | Deterministic report generation | Synthetic baseline/candidate yields verifiable JSON and Markdown reports |

Phase gate: synthetic security regression can be replayed and reviewed without VPS workloads.

## Phase 2 — Disposable Kubernetes proof (proposed v0.13–v0.14)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-12 | Pinned VM definitions | Offline non-executable schema, synthetic examples and capacity estimator; actual OS/kernel/K3s/CNI asset digest verification and VPS measurements remain a separate human-approved gate |
| SC-13 | Disposable VM adapter | SC-13a offline lifecycle/fault simulation plus SC-13b1 local artifact hashes, SC-13b2 offline signature/snapshot gates, and SC-13b3 explicitly invoked read-only host facts, and SC-13b4 non-executing QEMU argv blueprint and SC-13b5 offline resource supervision/fencing model and SC-13b6 developer-only private reservation record/quarantine; **real** approved KVM create/teardown, trusted software provenance, isolation, resource measurements and crash cleanup remain the SC-13 human/runtime gate |
| SC-14 | Dedicated K3s VM | Version-pinned isolated cluster reaches readiness and reliably cleans up |
| SC-15 | In-guest test/evidence transport | Reviewed harness executes with constrained access and returns bounded evidence |
| SC-16 | RBAC behavioral assertion | Expected-denial/allowed controls verify real API response under exact identity |
| SC-17 | Baseline/candidate differential | Intentionally weakened RBAC config produces a reproducible regression report with verified cleanup |

Phase gate **A**: first real repeatable Kubernetes security regression. Keep environments sequential initially on the constrained VPS.

## Phase 3 — Reviewed Kubernetes test packs (proposed v0.15)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-18 | Admission security pack | Positive/negative checks verify rejected/allowed pod specs |
| SC-19 | NetworkPolicy security pack | Known CNI enforcement, convergence, allow/deny controls and no unsafe egress |
| SC-20 | Versioned pack registry | Reviewed immutable pack manifests, compatibility and approved parameters |
| SC-21 | Repeatability/compatibility | Flaky conditions, unsupported environments and environmental drift reported explicitly |

Phase gate: useful RBAC, admission and network security coverage with meaningful controls.

## Phase 4 — Hosted platform and workers (proposed v0.16–v0.17)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-22 | Platform data model/migrations | Users, projects, specs, runs, artifacts and audit metadata |
| SC-23 | Durable job coordination | Leases, fencing, heartbeats, retry, cancellation and idempotency |
| SC-24 | Outbound authenticated worker | Independent job validation, resource limits and scoped results |
| SC-25 | Cloudflare API and beta authentication | Authorized submission/status/retrieval; no public experimental execution |
| SC-26 | Private R2 evidence | Upload integrity, access control and retention metadata |
| SC-27 | React results dashboard | One private beta researcher runs an approved end-to-end experiment from web UI |

Phase gate **B**: first hosted, one-tenant end-to-end demonstration.

## Phase 5 — Safe multi-user platform (proposed v0.18–v0.19)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-28 | Tenant-aware authorization | Users/projects/roles enforced on every API, job and evidence operation |
| SC-29 | Quotas and approval policy | Budgets for CPU/RAM/disk/runtime/concurrency and reviewed profiles |
| SC-30 | Worker failure recovery | VM cleanup and job reconciliation across crashes, restarts and expiration |
| SC-31 | Evidence privacy and disaster recovery | Retention, deletion, encrypted independent backups and verified restore |
| SC-32 | Security integration review | Cross-tenant negative tests, malicious-input tests, auditability and isolation evaluation |

Phase gate: independently authorized users cannot cross project boundaries; failure and recovery behavior is demonstrated.

## Phase 6 — Commercial/release validation (v1.0)

| ID | Milestone | Acceptance gate |
| --- | --- | --- |
| SC-33 | Design-partner trials | At least two independent pilots complete approved, useful upgrade-security checks |
| SC-34 | Operator and user readiness | Self-hosted setup, compatibility matrix, on-call runbooks, onboarding and supported upgrade path |
| SC-35 | v1.0 release qualification | All release gates pass; clean install and multi-user scenario verified; owner approves publication |

**v1.0 definition:** a secure web app for authorized researchers to select a reviewed experiment, configure baseline/candidate, safely execute in separate disposable environments, compare results and export reproducible evidence, with project isolation, quotas and reliable operations.

## Deferred after v1

Arbitrary executable user submissions; exploit/escape reproduction; continuous fuzzing; public unreviewed pack marketplace; complex multi-cloud autoscaling; automatic production control-plane operation on Kubernetes; sophisticated billing. Each future high-risk workload requires specific provider authorization and an approved execution environment.

## Dependency priorities

1. Contract and comparator first (SC-05–11).
2. Parallel **feasibility spike** for nested K3s resource/network/storage requirements, without authorizing a new VM run yet.
3. Prove the real regression (SC-12–17) before prioritizing SaaS polish.
4. Keep Dagu/systemd for trusted operations while the new engine/worker boundary matures.
5. Validate users before opening a broad public hosted execution service.

See [vision](PRODUCT_VISION.md), [architecture](ARCHITECTURE.md), [contract](EXPERIMENT_CONTRACT.md) and [development workflow](DEVELOPMENT_WORKFLOW.md).
