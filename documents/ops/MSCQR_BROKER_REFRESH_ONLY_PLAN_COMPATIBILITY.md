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
