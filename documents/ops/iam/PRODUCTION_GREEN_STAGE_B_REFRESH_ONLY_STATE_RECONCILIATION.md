# Stage B exact refresh-only state reconciliation

This is a one-purpose production control-plane contract. It exists because five previously authorized runtime IAM policy corrections were later reconciled into Terraform source, while the Stage B state at lineage `4e438e59-8b8b-194d-030c-5ede0c26344a`, serial `104` retained ten stale provider observations.

It is not a generic Terraform-drift override. It accepts only the ten addresses in `scripts/aws/production-green-stage-b-state-reconciliation.mjs`, only a refresh-only plan, and only zero remote resource operations. Any source, Terraform root, state lineage/serial, plan hash, ticket, tfvars, binding, preflight, address, output, policy-value, or provider-state deviation fails closed.

The protected preparation workflow carries the saved plan and bound inputs as one authenticated, short-lived artifact. Authorization and execution accept only that exact preparation artifact and its single authenticated authorization artifact; no Terraform plan is accepted through workflow-dispatch input.

The ceremony has three separate phases:

1. `npm run stage-b:state-reconcile -- --mode prepare` creates the exact reviewed refresh-only plan and private preparation evidence using the canonical release-deployer session.
2. The dedicated `Authorize Stage B refresh-only state reconciliation` workflow obtains an independent `production` environment approval and produces a bound authorization artifact.
3. The dedicated execution workflow rechecks protected main, state lineage/serial, every bound input, and applies only the saved refresh-only plan. It then proves both refresh-only and normal read-only closure are clean.

The authorization is one-shot in practice: a successful reconciliation advances the exact serial CAS, so replaying the same authorization fails before another state write. Relocation approval binds the path-independent logical artifact mapping and hashes; preparation and execution may therefore use different runner-private roots. Each phase still authenticates its own 0600 runtime files, while the saved refresh-only plan remains the exact approved binary and is applied without a replacement plan or execution var-file. The execution workflow never accepts a normal plan and never generates a replacement plan.
