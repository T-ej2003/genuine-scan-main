# Broker publication intent recovery

The publication authorization and source reservation are one-use. `PUBLICATION_INTENT` proves that the authorized operation was prepared; it does not prove Terraform entered AWS. New publications write an independent, write-once `STAGED_BROKER_PUBLICATION_DISPATCH` record immediately before the saved Terraform apply. The existing Terraform runner sets `AWS_MAX_ATTEMPTS=1`; the dispatch record remains the replay boundary regardless of provider retry behavior. The record binds the authorization digest, preparation digest, saved-plan digest and exact source.

On recovery, authenticate the original signed preparation, authorization, reservation, intent, protected source, saved plan, prerequisites and live alias. Then:

| Native evidence | Decision |
| --- | --- |
| Exact Terraform successor, matching Lambda version/configuration, unchanged alias, and new-contract dispatch | Reconstruct and persist the ordinary `PUBLISHED` receipt. Do not apply again. |
| New-contract intent, no dispatch, exact original Terraform lineage/serial/state, matching `$LATEST` code/configuration/last-modified and no newer Lambda version, approval still fresh | Continue the *same* authorized operation through an atomic dispatch claim and one saved-plan apply. A racing claim stops the second executor. |
| Dispatch exists but Terraform has no complete authenticated successor | `OUTCOME_UNKNOWN`. Do not apply again. |
| Legacy intent without the new dispatch contract and no complete Terraform successor | `OUTCOME_UNKNOWN`. Absence of a marker says nothing about a legacy executor. |
| Expired approval before dispatch, changed source/plan, altered predecessor, missing native proof, or conflicting lineage | Stop. Require newly governed authorization or a separate successor release. |

The original `CHG-20261022-001` publication is a **legacy intent**. Its Terraform state stayed at serial 148 and Lambda version/alias at 21, but the old executor had no dispatch marker. It must not be retried under its expired approval. Its completed registration, pruning and policy receipts remain reusable after native authentication.

## Successor release after this change merges

1. Record the new protected-main SHA and authenticate the original coordinator and live AWS state. Require all old jobs to be terminal and the original approval to be expired; do not reset its journal.
2. Establish whether `CHG-20261023-001` may be formally rebound from its failed, pre-mutation source attempt to the new SHA. If not, issue a new ticket. Do not silently reuse its old `SOURCE_ACCEPTED` checkpoint or image authorization.
3. Produce fresh image and web authorization for the new SHA according to the source impact contract. Reuse exact published image digests only if the signed impact calculation permits it.
4. Start the new-source Release Train with the authenticated original registration source/ticket as its completed-registration reference. The coordinator authenticates the native task-registration receipt and image compatibility, then performs only incomplete broker transitions under fresh protected approval. Do not claim a completed broker closure from the original ticket.
5. Proceed to trusted-terminal Stage B and Release Gates only after the new release's broker terminal closure, private bridge inputs and all other prerequisites authenticate. The 900-second root TTL, independent checker and MFA controls remain unchanged.

No historical `PUBLISHED` receipt or no-effect signature is synthesized by this procedure. A future incident with a dispatched but incomplete publication remains a separately reviewed recovery case.

## Review and validation

The native adapter verifies the signed intent and owned reservation, exact saved plan and protected source before accepting a recovery attempt. A pre-dispatch continuation also compares the complete Terraform predecessor with the saved plan, checks the full Lambda `$LATEST` identity/configuration through the reviewed Stage B validator, requires `State=Active` and `LastUpdateStatus=Successful`, matches code/environment/modification time, inventories published versions, and requires an unchanged alias. Both normal publication and recovery run this native proof immediately before the dispatch claim; recovery repeats it after its earlier proof. The dispatch claim uses the existing conditional, write-once S3 reservation; a lost claim response never grants apply ownership. Terraform runs with `AWS_MAX_ATTEMPTS=1`. A dispatched apply with an unchanged or partial successor remains blocked even if its AWS response was lost.

Local hostile cases cover forged/missing dispatch evidence, changed Terraform or Lambda predecessors, inactive/failed/updating Lambda state, missing readiness fields, an orphan version, alias drift, an expired approval, duplicate apply, a lost Terraform response, and recovery after a lost completion receipt. The Stage B control-plane suite, workflow parser, typecheck, build, security scope lint and security guardrails passed on the implementation branch. These tests do not authenticate a future live successor ticket, image authorization, or production approval; those remain required at execution time.
