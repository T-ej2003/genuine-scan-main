# Stage B pre-publication registration predecessor

Fresh task-definition registration can precede broker policy convergence and
publication. During that interval, the broker policy may authorize the
authenticated previously registered successors while the reviewed Lambda
alias remains on the latest published runtime version. Those task maps are
allowed to differ only when the canonical registration and terminal policy
receipt chains prove the policy-side successors and the live alias snapshot
proves the current published predecessor.

The explicit `predecessorReceiptRecovery` input to `prepare-registration`
contains only the two transaction IDs. The runner authenticates the durable
receipts, registered definitions, live policy, alias target and revision,
alias runtime map, and `$LATEST` map; it binds their identities into the
schema-3 preparation. Authorization and registration reauthenticate that
preparation. Read-only `recover-registration` also checks the same signed
predecessor identities against the live policy and alias before classifying
an uncertain registration result; it never retries registration.

After registration, `prepare-policy`, `authorize-policy`, and
`converge-policy` may consume the predecessor only through the authenticated
schema-3 registration handoff. They reauthenticate that handoff, then verify
the live historical policy map and older alias map against the exact signed
predecessor. The fresh registration map remains a separate identity and is
the policy convergence target. This exception is not accepted from a caller
field and is not available to publication, cutover, or policy recovery.
Policy recovery continues to authenticate its saved policy transaction and
classify exact pre/post policy state; it does not use the predecessor-state
reader. Once policy convergence succeeds, later publication and cutover use
the ordinary prerequisite chain.

This evidence is predecessor provenance only. The historical image-impact
report remains incompatible, so the old registration cannot become a current
release handoff. Fresh current-main task definitions and the existing
registration authorization are still required. Preparation performs reads
and plan capture only; it does not register definitions or mutate IAM, Lambda,
ECS, Terraform state, or the database.


## Recovery and mandatory policy evidence

Registration recovery authenticates retained historical ECS revisions against
immutable, version-pinned registration receipts. It does not require those
revisions to remain Terraform's current resource bindings after fresh apply.
The historical policy receipt still authenticates the original state identity;
the current state must retain its lineage and advance its serial, while its
broker policy resource and live IAM default/document remain exact. The existing
read-only recovery classifier separately verifies every current task-definition
binding and ECS successor against the original authorized saved plan. Partial,
substituted, or ambiguous successors cannot terminalize and cannot be replayed.

The public `prepare-policy`, `authorize-policy`, and `converge-policy` paths
require the receipt-bound historical policy entry when registration is schema
3. The entry's transaction, receipt objects, receipt chain, result digest and
registered map must match the signed registration predecessor; the live policy
and alias are independently reauthenticated. Missing evidence fails before
plan capture or signing. Authorization binds the full mixed chain and its
checker disclosure. After convergence, publication authenticates that exact
signed policy package, including its historical evidence, and the fresh live
successor; it does not reinterpret the historical policy as the current policy.
Publication and cutover retain their own authorization boundaries.

| Boundary | Historical expectation | Current expectation | Authority |
| --- | --- | --- | --- |
| Registration preparation/execution | Retained receipt revisions equal current pre-apply bindings | Exact old alias and historical IAM predecessor | Fresh registration authorization for apply |
| Registration recovery | Retained receipt revisions remain authentic in ECS | Exact fresh plan successors in advanced Terraform state and ECS | Read-only diagnosis; no registration replay |
| Policy preparation/signing/convergence | Mandatory receipt-bound policy matches signed predecessor | Fresh registration outputs; exact old alias and IAM predecessor | Separate policy authorization binds complete evidence |
| Completed policy handoff/publication | Historical evidence remains in signed policy package | Fresh policy and registration successors agree | Separate publication authorization |
| Cutover | Publication provenance retained | Exact fresh predecessor/RevisionId CAS | Separate cutover authorization |
