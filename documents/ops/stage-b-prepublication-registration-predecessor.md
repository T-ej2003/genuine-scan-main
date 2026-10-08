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
preparation and repeats those checks when authorization and registration
consume it. Ordinary preparation still requires the strict matching task-map
identity.

This evidence is predecessor provenance only. The historical image-impact
report remains incompatible, so the old registration cannot become a current
release handoff. Fresh current-main task definitions and the existing
registration authorization are still required. Preparation performs reads
and plan capture only; it does not register definitions or mutate IAM, Lambda,
ECS, Terraform state, or the database.
