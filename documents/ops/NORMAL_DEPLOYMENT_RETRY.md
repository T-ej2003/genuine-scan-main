# Normal deployment retry boundaries

Authority is the fixed IAM-protected production DynamoDB item, not ECS source tags alone and not workflow history. The normal OIDC executor writes a bounded `normalDeploymentReceipt` in that item using the same generation CAS as component state. No additional AWS permission, table, operator artifact or signing step is introduced.

The receipt binds canonical workflow/run, source, plan hash, immutable image references, predecessor identities and exact registered task definitions. It cannot attest recovery or rotation. `VERIFIED` is written only after the complete affected release passes stability, readiness and authenticated application smoke. Component commit consumes that receipt and advances every affected component in one conditional write.

| Interruption | Next current-main run |
| --- | --- |
| Image publication | Reuse authenticated immutable publication; no service/state identity changed. |
| Registration before durable candidate record | No service update was allowed; discard the empty intent after predecessor verification. Historical registered revisions are not deleted. |
| Candidate record / ECS update / stability / readiness / smoke before verified receipt | Authenticate exact predecessor/candidate identities; restore any recorded live candidates, verify predecessors and clear intent. Never adopt unverified work. |
| Verified receipt before component CAS | Authenticate recorded candidates against task definitions, image/source identity, live services and fresh health/smoke; commit all affected components first, then classify the new source range. |
| Ambiguous component CAS | Strong read sees either pending receipt with old components, or atomically committed components without receipt. No second service mutation or duplicate component advancement. |
| Interrupted rollback | Persisted intent remains; retry restores only remaining exact candidates. Unknown live identities or failed rollback stay fail-closed. |

The workflow retains exact current-main execution and its shared production concurrency group. Reconciliation runs before classification/publication and uses the protected normal-deployment environment. Backend-only/front-end-only transactions do not advance other components. Ordinary no-op commits do not advance component identities.

An authenticated security/recovery terminal can supersede the pending identity of a component it actually establishes. The same state CAS removes only that component from the pending receipt; other pending components remain recorded for rollback, never for partial normal commit. Unrelated security/database updates preserve the receipt unchanged.

## Bounded review findings addressed

- Runner-local journals did not survive every interruption and could not authorize an older live candidate after main advanced: persist the intent/receipt before the relevant boundaries.
- Comparing a current candidate's SHA/digest was not activation authority: activation now requires the recorded predecessor, and reconciliation requires the exact durable receipt.
- A receipt must not become a half-release commit: verified backend/frontend identities are committed together and consumed in the same CAS.
- Receipt persistence must precede both backend and frontend updates: registration readback hooks persist exact target identities before update adapters run.
- A task-definition image alone is not runtime proof: verification checks service convergence and actual running task digests before receipt completion.

Operational recommendation: alert on repeatedly failing normal workflows or an aged pending receipt. Keep unknown-state rejection intact; never add an automatic arbitrary-target adoption rule to improve availability.
