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
