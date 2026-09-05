# Production initial-activation lifecycle policy reconciliation

Authorization and result artifact uploads each run under `always()`, so a failed authorization upload cannot skip an existing result's publication attempt. Missing files and upload failures remain fatal; neither step ignores errors or fabricates evidence.

Capability evidence models seven shared STS/IAM reads twice: `ROOT_OPERATOR` read-only preparation through `--prepare`, and `INITIAL_ACTIVATION_RECONCILER` workflow execution. Only the latter owns the `iam:CreatePolicyVersion` edge. Root preparation uses the existing authenticated-root/source-contract authority representation; the OIDC execution edges remain bound to the reconciler permissions policy.

The exact `iam create-policy-version` subprocess forces `AWS_MAX_ATTEMPTS=1` after credential-environment construction. One callback therefore permits only one CLI request attempt; ambiguous outcomes use authenticated readback. Read subprocesses retain the existing credential wrapper's retry configuration.

IAM `ServiceFailure` is included in the exact post-mutation transient read-error allowlist. HTTP status 500 alone does not authorize retry; pre-mutation failures remain immediate failures.

Post-mutation readback uses at most six snapshots. Exact AWS throttling and service-availability error codes from any snapshot read consume that existing retry budget, as does the reviewed policy-version propagation condition. Authorization, CAS, malformed responses, and unexpected topology remain fail-closed. Readback retries never repeat `CreatePolicyVersion`.

`PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION` is a one-target governed repair for `arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle`.

It accepts only the authenticated `v1` predecessor with SHA-256 `2a90146c8fc8f6062198650134c0e92724cc4dd69720bde629fd0752e4432c71`, or an already-reconciled source document. The desired document is always `documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json` with SHA-256 `7e9eef0b5dd5c089f4734a43cbc40ed963078dc500828c2e592cc07f04c6d564`.

The approval artifact binds the protected source, exact target, predecessor, desired document, complete release-role policy set, target-policy entity boundary, version count, and a single `iam:CreatePolicyVersion` request with `SetAsDefault=true`. The target policy may be attached only to `mscqr-production-release-deployer`, with no users, groups, or permissions-boundary usage. It authorizes neither policy attachment changes, `iam:SetDefaultPolicyVersion`, nor `iam:DeletePolicyVersion`; the production-environment approval freshness limit is checked again immediately before the write.

The executor runs only inside the protected GitHub Actions workflow under the purpose-bound `arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler`, rereads the exact live state immediately before mutation, and performs one create at most. GitHub's non-cancelling `production-deploy` concurrency serializes production mutation workflows; no local root or S3 reservation is part of this operation. It requires post-write readback of a new default version with the exact desired canonical document and unchanged attachments. If a response is lost after AWS accepted the create, exact desired readback finalizes completion without another version creation.

## Runtime review and recovery contract

The workflow authenticates repository, freshly protected main and clean checkout, obtains actual production environment approval, creates the bound authorization, assumes only the reconciler role, and invokes the runner. The runner authenticates source again, checks the workflow/run/attempt and STS identity, authenticates the private authorization bytes and approval bindings, preflights the result destination, and performs two live snapshots plus a fresh approval-age check before the single write. No shell or application mutation retry exists. Workflow reruns (`GITHUB_RUN_ATTEMPT != 1`) are rejected both before credential acquisition and inside the runner before AWS access: historical approval observations must not reauthorize an ambiguous attempt.

| Actual AWS action | Resource | Root `--prepare` | OIDC execution | Retry boundary |
| --- | --- | --- | --- | --- |
| `sts:GetCallerIdentity` | `*` | Identity check | Identity check, before mutation | CLI reads only; application fails closed |
| `iam:GetPolicy` | Target lifecycle policy | Read | Predecessor, CAS, convergence | Read rule below |
| `iam:GetPolicyVersion` | Target lifecycle policy/default version | Read | Predecessor, CAS, convergence | Read rule below |
| `iam:ListPolicyVersions` | Target lifecycle policy | Read, capacity check | Predecessor, CAS, convergence | Read rule below |
| `iam:GetRole` | Exact release-deployer role | Read | Predecessor, CAS, convergence | Read rule below |
| `iam:ListAttachedRolePolicies` | Exact release-deployer role | Paginated read | Predecessor, CAS, convergence | Read rule below |
| `iam:ListEntitiesForPolicy` | Target lifecycle policy | Paginated read | Predecessor, CAS, convergence | Read rule below |
| `iam:CreatePolicyVersion` | Target lifecycle policy, exact source document, default=true | **Unreachable** | One invocation after CAS | **CLI total attempts=1; never retried** |

Each of the seven shared reads has distinct `ROOT_OPERATOR` preparation and `INITIAL_ACTIVATION_RECONCILER` execution graph/closure edges. Root uses the existing root/source-contract authority model (`ADMIN_DIRECT_READ`); OIDC calls use `GITHUB_OIDC_IAM_POLICY_READ` or `GITHUB_OIDC_IAM_POLICY_RECONCILIATION`, bound to `infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json` and live `MSCQRProductionInitialActivationPolicyReconciler`. The lifecycle policy is the **target**, never the execution authority. Legacy capability ID suffixes containing `root` are identifiers, not principal attribution; identity fields are authoritative.

Read rule: existing CLI read retries are unchanged. Only post-mutation convergence may repeat a snapshot, at most six observations with five bounded delays. Exact allowlisted service codes and canonical botocore endpoint-connection, connect-timeout, read-timeout and connection-closed diagnostics for `https://iam.amazonaws.com/` consume this budget. Botocore maps reset/protocol failures to its connection-closed diagnostic. Arbitrary timeout text, wrong endpoints, TLS validation failures, access/validation errors and semantic/security failures do not qualify. The diagnostic contract comes from [botocore exceptions](https://github.com/boto/botocore/blob/develop/botocore/exceptions.py) and [HTTP session error mapping](https://github.com/boto/botocore/blob/develop/botocore/httpsession.py). Exhaustion throws without success or a second write. Pre-mutation failures never enter this loop.

| Termination point | Available evidence and required behavior |
| --- | --- |
| Before mutation | No write; failed prerequisites cannot authorize execution. |
| During request / after acceptance / before readback / during readback | Outcome may be ambiguous. Authorization upload is attempted if the runner survives; logs may remain. There is **no guarantee** of a durable result after runner loss. Stop and inspect live state read-only; never rerun the job or blindly dispatch another mutation. |
| After exact readback and result generation | Result contains the authorization binding and exact successor hashes. Both required uploads are attempted independently. |
| During either upload | Upload failure remains fatal. The other upload still runs if the runner survives; missing result is an error, not synthesized completion. |

Recovery is an operator decision based on fresh read-only policy/version/topology evidence. Exact successor can be verified without a write; predecessor still observed is not proof that an ambiguous request was never accepted. Unexpected state fails closed. A new dispatch is not automatic recovery. GitHub concurrency coordinates repository workflow runs, not arbitrary external administrators; external IAM writers remain outside this authority contract.

The engineering regression matrix exercises the real snapshot for all service codes and transport diagnostics at every read, successive failures/exhaustion, pre-mutation failures, non-transient false positives, actual mutation subprocess environments, lost-response recovery through the runner, rerun rejection, CAS/freshness/version capacity, wrong identities/bindings, independent artifact uploads, graph authority drift and preparation/execution identity coverage. No additional IAM capability or production mutation is part of this source review.
