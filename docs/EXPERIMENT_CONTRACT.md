# Proposed experiment and evidence contracts (design only)

**Status: v0.12 begins with offline, schema-based YAML/JSON validation only.** The package `slipcage_engine` recognizes the example profile as **definition data**, not a reviewed executable test pack. SC-08 adds a bounded, **synthetic fixture-only** interpreter; SC-09 adds **local synthetic-only** evidence bundles and read-only verification. SC-10 now implements **synthetic evidence-gated differential comparison**. No real Kubernetes executor, environment-to-environment comparator, report generator, worker, VM provisioning or Kubernetes adapter has been introduced. See [current CLI limitations](ENGINE_CLI.md).

## Goals and boundary

A portable, versioned contract should represent a **reviewed assertion**, immutable environment inputs, explicit expected security behavior, bounded execution policy, and evidence. A spec is **data**, never a command script. Parameter values must not influence worker shell evaluation, file paths outside approved roots, Kubernetes identities outside owned clusters or unrestricted network targets.

### Example experiment definition

~~~yaml
api_version: slipcage.dev/v1alpha1
kind: SecurityExperiment
metadata:
  id: kubernetes.rbac.pod-create-denied
  version: 0.1.0
profile:
  id: kubernetes.rbac
  pack_version: 0.1.0
parameters:
  namespace: slipcage-test
  subject: restricted-service-account
assertions:
  - id: restricted-create-pod
    operation: create_pod
    expected: denied
limits:
  timeout_seconds: 120
  max_artifact_bytes: 1048576
~~~

A future run request references **one immutable experiment/pack digest** and two environment definitions (`baseline` and `candidate`), rather than embedding unreviewed runnable code in the experiment spec. Environments must pin exact image digests, K3s version/build or digest, relevant cluster policy and supported CNI, with validated variable boundaries. A candidate may change an approved configuration or software version, but the assertion itself should remain identical.

### Proposed engine interfaces

| Interface | Input | Output / obligation |
| --- | --- | --- |
| `validate_spec` | Untrusted YAML/JSON document and profile registry | Typed spec or deterministic validation error; strict limits |
| `prepare_environment` | Pinned environment definition + budget | Environment handle or typed failure; cleanup registration |
| `execute_assertion` | Reviewed assertion ID, validated parameters, environment handle | Bounded raw observation + normalized outcome |
| `collect_evidence` | Attempt and bounded artifacts | Private canonical manifest and SHA-256 digests |
| `compare` | Two verified results for the same assertion | Change classification or `incomparable` with reason |
| `render_report` | Comparison and verified evidence | Stable JSON and human-readable Markdown |

`validate_spec_bytes` and `load_spec` now implement schema-based offline parsing/validation for the restricted RBAC example profile. The `slipcage validate` CLI works; `slipcage run`, `slipcage compare` and `slipcage report` exist only as explicit nonzero-refusal placeholders. The other interface names remain design proposals, **not existing Python functions**. A future hosted worker should call the same core engine rather than duplicating semantics.

## Assertion result semantics

**SC-07 implementation note:** `slipcage_engine.results` now provides typed
`Observation`, `AssertionResult` and `result_for_observation` primitives.
They revalidate the source definition, enforce declared assertion IDs, and
map normalized observation status to outcome without conflating infrastructure
errors with security-boundary failures. The `verified` status remains a
**trusted-adapter claim only**; no Kubernetes request, evidence verification,
result replay, differential comparison or runnable CLI is implemented yet.
The JSON serialization explicitly says `evidence_status: not_collected`.


| Outcome | Meaning | Example |
| --- | --- | --- |
| `PASS` | Observed behavior matches the security expectation | Restricted subject receives a verified authorization denial |
| `FAIL` | The boundary demonstrably behaves contrary to the expectation | Restricted subject successfully creates an otherwise disallowed pod |
| `ERROR` | Execution or infrastructure problem prevents a valid observation | K3s unavailable, API unreachable, guest crashed |
| `SKIP` | An explicitly recorded prerequisite is unsupported/not applicable | NetworkPolicy pack against a known incompatible CNI |
| `INCONCLUSIVE` | Observation is insufficient/ambiguous | API response cannot reliably distinguish denial from transient failure |

A security assertion is not a process exit code. A Kubernetes 403 can be a **PASS** for a denial assertion if the identity, resource, namespace and error semantics are verified; an ambiguous 403 is not automatically proof. An API error, absent evidence or unexpected environment must never be silently interpreted as the asserted security behavior.

### Differential classifications

- `unchanged_pass`: baseline PASS, candidate PASS.
- `regression`: baseline PASS, candidate FAIL, compatible verified observations.
- `improvement`: baseline FAIL, candidate PASS, compatible verified observations.
- `unchanged_fail`: baseline FAIL, candidate FAIL.
- `incomparable`: either side ERROR, SKIP, INCONCLUSIVE, missing/invalid evidence, incompatible assertion contract or unsupported comparison.

Preserve the two raw outcomes alongside the classification. Future policy may distinguish *expected changed behavior* from an undesirable regression, but the raw difference must be preserved.

### Synthetic fixture results (SC-08)

`slipcage run-fixture` accepts the validated definition and one of five
bundled observation scenarios. It emits deterministic, explicit
`synthetic_offline_fixture` results (including cancellation/deadline state)
with `security_test_executed: false` and `evidence_status: not_collected`.
The fixture is not a Kubernetes adapter, does not authenticate an API
observation, and does not provide independent evidence. Actual on-host
workloads and evidence bundles remain separate approval milestones.

### SC-09 — implemented local synthetic evidence subset

The offline engine can now write and re-verify a **new private directory**
with `experiment.json`, `results.json`, `provenance.json`,
`checksums.json`, and `manifest.json`. The manifest is written last.
The verifier rejects incomplete or unsafe artifacts, checks SHA-256 digests,
revalidates the experiment, and replays the **packaged synthetic fixture**.
The result explicitly states `real_security_evidence_verified: false`.
These files contain no real Kubernetes API observations, guest provenance,
real run IDs, signed attestation, or project authorization. See
[SC-09 CLI details](ENGINE_CLI.md).

### SC-10 — implemented synthetic comparison subset

`compare_fixture_bundles(baseline, candidate)` and
`slipcage compare-fixtures` reverify both private synthetic bundles before
normalizing PASS/FAIL into `unchanged_pass`, `regression`, `improvement`,
or `unchanged_fail`. A pair with PASS/FAIL and FAIL/PASS assertions is
`mixed_change`; missing, corrupted, inconsistent or unsupported observations
are `incomparable`. The real `compare` CLI remains disabled. Every output
explicitly says it is synthetic and does **not** verify real Kubernetes
security behavior. See [offline comparator rules](ENGINE_CLI.md).

## Minimum evidence bundle (proposed)

~~~text
run/
  manifest.json              # schema, IDs, attempts, timestamps, digests
  experiment.json            # canonical validated definition (no credentials)
  environment.json           # pinned inputs and observed runtime versions
  observations/
    restricted-create-pod.json
  results.json               # outcomes, reasons, timing, environment status
  checksums.json             # sha256 for each regular bounded artifact
  report.json                # comparator output when paired
  report.md                  # human-readable summary when paired
~~~

Manifest needs `schema_version`, `run_id`, `attempt_id`, `project_scope` (redactable for public export), `experiment_digest`, `pack_digest`, `environment_digest`, `worker_version`, `started_at`, `completed_at`, `cleanup_status`, `outcome` and structured failure reason. Reserve explicit fields for provenance unavailable or unverified; never invent a digest.

For security and correctness: create files with private permissions; enforce byte/file-count/path caps; refuse symlinks, path traversal, ambiguous JSON or duplicate IDs; redact bearer tokens, kubeconfigs and credentials; produce deterministic JSON normalization where possible. A SHA-256 hash by itself is **not** an authenticated signature. Store evidence under access-controlled roots and eventually verify artifacts on both worker and control-plane boundaries.

## API and worker compatibility rules

- Experiment specs and results are **versioned separately**. Unknown major versions fail closed rather than being interpreted as a known contract.
- The reviewed profile registry binds an experiment ID to trusted implementation; user parameters are validated against strict allowlists/typed bounds.
- Run creation and worker claim must be authorized by project, profile, environment and budget. Worker identity is separate from researcher identity.
- A job attempt has a unique ID and fencing token. Expired leases require reconciliation; two attempts must never share mutable run storage.
- Cancellation and timeout create explicit incomplete evidence and trigger bounded cleanup, not a false security PASS.
- Replays record environmental differences and nondeterminism; "pinned" means recorded immutable inputs, not guaranteed byte-for-byte results.

## Contract acceptance milestones

1. Offline fixtures validate valid/invalid specs and strict bound checks.
2. Known PASS/FAIL/ERROR/SKIP/INCONCLUSIVE cases produce stable normalized evidence.
3. Synthetic baseline PASS vs candidate FAIL produces a regression and a verifiable report.
4. Missing/corrupt/incompatible evidence produces `incomparable`, never a fabricated regression.
5. The same engine interfaces later operate against disposable K3s VMs; no hosted service is needed for the first proof.

See [architecture](ARCHITECTURE.md), [roadmap](V1_ROADMAP.md), [development workflow](DEVELOPMENT_WORKFLOW.md).
