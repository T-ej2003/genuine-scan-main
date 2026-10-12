# Completed pruning handoff into broker publication

Release Train run 38253944150 adopted all twelve registrations from source
2c2d63e and completed authorized policy pruning and convergence. Publication
preparation then rejected the signed policy predecessor at
stage-b-staged-broker-executor.mjs:1356. Its actual chain was
`{registration, pruning}`; the validator expected `{registration}`. The
registration evidence was identical. This is a verifier compatibility defect,
not a missing registration or failed pruning mutation.

Read-only authentication confirmed native pruning and policy-convergence
receipts, their original protected authorizations, live default policy v15,
released policy ownership and Terraform serial 124. Version v10 was deleted by
the authorized pruning operation. Historical broker alias v13 remains adopted.
Do not repeat those operations.

The normal schema-2 policy verifier now retains the exact registration binding
and authenticates any signed pruning predecessor through the existing pruning
handoff verifier. That verifier checks authorization at the historical operation
time, reservation, native intent, native result and ownership evidence. It does
not compare historical pruning inventory with the later converged live policy.
Unexpected predecessor fields, altered registrations or pruning receipts, and
missing authentication remain rejected. Schema-3 and terminal-adoption routes
are unchanged.

Regression coverage executes the public coordinator from capacity pruning
through publication and closure, and exercises cross-source schema-2 adoption
through pruning, convergence and publication without another registration.
Negative coverage rejects altered authorization/receipt identities, substituted
registrations, unknown predecessor members and missing native authentication.
All external mutation boundaries in these tests are mocked.

After merge, authenticate the new protected-main SHA, exact-source checks,
explicit CHG ticket scope and canonical image reuse before dispatch. Preserve
and reauthenticate the completed source-6be5160 pruning/convergence receipts,
all original registration evidence, and the historical CAS/closure receipts.
Use the existing durable coordinator and protected approval path only; do not
repeat registrations, completed pruning or policy writes. A changed source
requires fresh source-bound authorization where the current operation needs it.
No further Release Train run was dispatched while investigating this defect.

Recommendation: preserve the signed predecessor chain through every handoff;
never remove its completed-operation evidence to satisfy a narrower comparison.
