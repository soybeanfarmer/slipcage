# Slipcage development, review and release workflow

This policy codifies the existing **human-controlled production process**. The implementation agent can propose designs, make code/docs/tests changes on a branch, diagnose CI and present PRs. **Only the human owner authorizes merge, release and VPS commands.** GitHub CI alone never proves production behavior.

## Roles and gates

| Stage | Implementation agent | Human owner |
| --- | --- | --- |
| Agree on milestone | Propose bounded scope, risks and acceptance tests | Approve scope |
| Build | Create branch; implement code, tests, docs | No intervention required |
| CI | Inspect failures, fix branch and share PR | Review proposed changes |
| Merge | Explain diff and remaining uncertainty | Review and merge PR |
| Release | Recommend exact version and manual release procedure | Promote approved GitHub release |
| VPS | Provide bounded explicit commands and expected observations | Run commands over SSH |
| Verification | Compare logs and deployed SHA; assess tested vs untested | Provide outputs and decide acceptance |
| Hotfix | Narrow branch/PR with reproducer/regression tests | Review/merge/publish/redeploy/verify |

The agent must not silently merge PRs, publish release tags, deploy, SSH, enable service timers, alter host firewall, restart services or run experiments. Explicit authorization for a milestone **does not** authorize any later production gate.

## Standard change cycle

1. **Proposal:** record scope, explicit non-goals, safety invariants, affected files, dependencies and acceptance criteria.
2. **Branch:** start from current `main`; use descriptive branch names such as `docs/v0.11-product-foundation` or `feat/experiment-contract`.
3. **Implementation:** favor small, reviewed PRs; preserve data and existing service behavior. New experimental workloads remain disabled unless separately authorized.
4. **Automated checks:** run unit tests, Python/shell/YAML/Ansible syntax and relevant offline negative tests. GitHub Actions supplies the authoritative remote CI status for its exact commit. CI constructs guest images **without** booting them.
5. **PR:** include summary, scope/non-goals, threat changes, exact CI SHA/result, evidence requirements, rollback considerations and the manual validation procedure.
6. **Human merge:** no auto-merge or branch-to-production promotion.
7. **Human release:** publish a stable version from `main` via the existing `Approve Slipcage Release` workflow, only after reviewing CI and changes. `production` environment approval, if configured, is a separate owner action.
8. **Human VPS deployment:** run the guarded pull-deploy service, inspect deployed SHA, then execute only the approved milestone-specific checks.
9. **Verification:** distinguish `implemented`, `released`, and `production-validated`. Record precise evidence, outstanding limitations and recommendation for next milestone.
10. **Failure:** do not hot-patch the VPS as a normal shortcut. Preserve evidence and prepare a focused fix PR with relevant tests. Operations that alter evidence, backing databases or other services require separate approval.

## Standard approved VPS deployment commands

**Use these only after an explicitly approved release and operator authorization.**

~~~bash
sudo systemctl start slipcage-pull-deploy.service
sudo cat /var/lib/slipcage/deployed-sha
~~~

The SHA must match the release commit. Check service journal and exact expected indicators before declaring success. In case of failure, preserve journal and error output; a successful release workflow does not mean deployment succeeded. Deployment drain/maintenance can intentionally remain active after failed installation; follow the existing operational runbooks before changing service state.

For documentation-only changes, a review plus source-level checks can complete the documentation work item, but does **not** independently validate VPS runtime. The release itself can still be deployed through the normal human-gated process if the owner chooses.

## Required safety invariants

- No unapproved QEMU or K3s workload launch. Existing guest experiments stay manual-only, benign and resource-bounded; no adversarial payloads or fuzzing.
- No unreviewed deletion, retention broadening or mutation of live DB, reports, guest evidence or backups.
- No implicit webhook endpoint, notifications, external credentials, automatic off-server backup configuration or internet-exposed dashboard. Encrypted off-server backup activation remains deferred.
- No untrusted input used as executable shell or as an unrestricted network target.
- Avoid private keys, passwords, host addresses, kubeconfigs, research evidence or webhook URLs in GitHub logs/PRs and chat.
- External hosted execution requires a new approved worker and tenant security gate, not an extrapolation of current Dagu permissions.
- A future Cloudflare release process must have its own clearly documented environment-specific human approval and post-deployment verification.

## Proposed repository governance (owner action required)

**Documenting these settings is not the same as enabling them.** At the v0.11 baseline the `main` branch was reported as unprotected. The owner should review and enable available branch protection/rulesets in GitHub repository settings, taking account of the account plan and solo-maintainer workflow.

Recommended settings, when supported:

- Require PRs before merging into `main`; do not allow force pushes/deletions.
- Require the repository's `validate` check from CI on the exact current PR head; optionally require the branch to be up to date before merge.
- Require conversations to be resolved before merge; use human self-review in a solo-maintainer project rather than implying independent code-review independence.
- Restrict bypasses and release/tag changes; use a protected `production` environment requiring explicit owner approval where supported.
- Keep GitHub Actions permissions minimal and do not grant the release workflow permission to bypass the PR/CI gate.
- If repository plan settings cannot enforce a desired protection, record the limitation and retain the manual approval gate.

**Governance verification:** owner confirms settings/ruleset enforcement in GitHub, demonstrates an attempted unreviewed/non-CI merge is blocked where practical, and notes any unsupported controls. The implementation agent must not claim branch protection is enabled based solely on adding this document.

## Milestone readiness evidence

For each release, archive:

- approved milestone scope, changed commit/tag/PR and remote CI result;
- deployed SHA if a VPS promotion was approved;
- safe, bounded runtime validation commands and their observed output;
- whether data/configuration changed, what was *not* exercised, and any safety exception;
- final state: implemented, released, production-validated or blocked.

Example failure precedent: a health-monitor permission regression should yield a focused hotfix PR with tests and a separately approved release, **not** a broad capability increase or an in-place server patch.

See [v1 roadmap](V1_ROADMAP.md), [architecture](ARCHITECTURE.md), [security policy](../SECURITY.md).
