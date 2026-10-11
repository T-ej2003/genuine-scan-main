# Broker closure refresh-only plan compatibility

## Failure and reproduction

Recovery run 38139629204 stopped at the shared plan-envelope resource_changes array assertion after closure authorization child 38139922342 succeeded. Durable readback showed no STATE_REFRESH_INTENT, no closure result, and Terraform state unchanged at serial 121. The completed reviewed-alias CAS remains version 13.

Terraform 1.15.8 was executed locally with an isolated built-in terraform_data fixture and a local backend. A real saved refresh-only plan, rendered with terraform show -json, had format_version 1.2, complete true, errored false, and omitted resource_changes. This involved no production API or remote backend mutation. The failed hosted plan bytes were not retained in its logs; the local reproduction demonstrates the omitted-field representation, not byte-identical recovery of that lost plan.

The existing IAM policy refresh-only contract already accepts this representation. Broker alias refresh validation now follows that behavior only in its explicit refresh-only context. It does not modify the raw plan or its authenticated hash.

## Security boundaries

Normal publication, cutover, and terminal closure plans still require resource_changes arrays. Present null, object, string, numeric and boolean values are rejected. Refresh resource entries still require known census addresses, managed non-deposed resources, exact no-op actions and equal known before/after values. Exact alias drift, output reconciliation, source identity, state lineage/serial/hash, authorization, and saved-plan binding remain unchanged.

The hosted regression resumes a saved CAS through protected authorization and the public reconciliation entrypoint using mocked external boundaries. It rejects refresh execution before approval, records state-only intent and the authenticated closure result, and adopts completed closure on restart without repeating alias CAS or refresh apply. Native executor regression independently proves a saved refresh-only plan with omitted resource_changes executes once only after authorization and durable intent, followed by strict normal closure validation.

## Operational handoff after merge

Reconcile protected main, the live reviewed alias v13, the completed historical CAS and existing closure attempt. Use the existing canonical recovery/authorization lifecycle; expired approval is not authority. Do not blindly replay the old attempt or extend its timestamps. Complete only authenticated closure reconciliation and then the existing Stage-B/rotation/release prerequisites. Do not republish the broker or repeat ECS/IAM operations. Production runtime and Startex acceptance remain separate required proof.

Recommendation: retain this focused compatibility coverage when updating Terraform versions. No additional orchestration or deployment capability is introduced.

## Exact-head review and audit follow-up

Codex review of 3c103188 identified a test portability defect: the shared system temporary directory can be mode 01777 on hosted Linux. The hosted regression now creates its own temporary directory, sets mode 0700, and removes only that test-owned directory afterward. The production private-directory validator is unchanged. All 23 hosted coordinator tests pass after correction.

The required audit independently rejected a stale executable-input reachability fingerprint. The unfiltered hosted OSV report from run 38142759278 (SHA256 89db110482f483311c6e4d064fd08215b4a3bc1e2e1366504685c06200bf2073) was retained unchanged. Its checkout path was relocated only in memory for local verification against the unchanged lockfiles. Canonical browser compilation and runtime packaging were rerun with physical isolated dependency paths. The 204-package browser closure excludes braces; the only reported HIGH finding remains braces@3.0.3 / GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 under the existing development-build-only acceptance. Its scope, owner, November 2 expiry, vulnerable version and security thresholds remain unchanged. Only the reviewed executable-input fingerprint and rationale advance. The final fingerprint is efd79d9225db624f47cc30a0f721c5aa3c422c326bf8365f7d50ef2ff3c13916. Hosted CI must rescan the final head independently.
