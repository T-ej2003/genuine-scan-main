# Broker policy execution and recovery state machine

Applies to convergence (one CreatePolicyVersion, SetAsDefault) and pruning (one approved non-default DeletePolicyVersion). S3 conditional one-use reservation is durable replay consumption; DDB fixed policy ownership serializes both purposes. A frozen, independently authenticated STS session is the only normal writer credential. Recovery proves credential unusability, never physical process termination.

| State | Durable evidence | Ownership | Authorization | IAM may have occurred | Normal next | Recovery next | Safe release | Safe IAM retry |
|---|---|---|---|---|---|---|---|---|
| PREPARED | Signed preparation/approval | absent/released | unused | no | reserve | new governed attempt | no owner | unused authority only |
| RESERVED | Exact S3 one-use reservation | absent/released | consumed | no | conditional acquire | read-only diagnosis; fresh authority if acquisition absent | no owner | never same approval |
| ACQUIRED_NO_MUTATION_POSSIBLE | Reservation + atomic DDB identity/acquisition metadata | held | consumed | no | authenticate/read predecessor | expiry proof + signed preparation/reservation + absent commit + compatible predecessor + recovery receipt | only after terminal receipt + exact completion | never |
| INTENT_ONLY | Above + exact S3 intent; DDB commit absent | held | consumed | no | conditional commit | validate intent; expiry proof; authenticate predecessor; no-write receipt | only after terminal receipt | never |
| MUTATION_INTENT_DURABLE | Above + DDB commit bound to intent hash | held | consumed | yes | one IAM invocation | expiry proof; exact predecessor or exact successor | only after authenticated terminal outcome | never |
| MUTATION_OUTCOME_UNCERTAIN | Same commit; no terminal receipt | held | consumed | yes | read-only diagnosis | exact predecessor => no-write; exact successor => success; ambiguous => retain | only exact outcome + receipt | never |
| TERMINAL_SUCCESS/NO_WRITE | Immutable terminal S3 receipt | held | consumed | outcome authenticated | exact DDB completion | reauthenticate/reuse exact receipt; complete | only after completion | never |
| REPLAY_COMPLETED | Above + DDB terminal receipt hash | held | consumed | outcome authenticated | owner/generation release | reauthenticate exact receipt/hash; release | yes, exact owner/generation | never |
| RELEASED | All above + released DDB row | released | consumed | outcome authenticated | future fresh authority/generation | read-only diagnosis; no held lock | already released | never same authority |

The initial map identified missing acquisition evidence and a success-only recovery receipt reader. The implemented correction is: atomic acquisition evidence within the existing DDB row; one conditional intent-hash commit before IAM; recovery accepts/authenticates the appropriate terminal variant and requires the commit for successor success. No new table, workflow, lock, signing mechanism or production action.

## Failure windows

At every held-state window the old writer may continue until independent pinned-STS expiry proof. Recovery therefore never releases merely from job termination, elapsed lock age, local error or missing receipt. After credential expiry a late old process cannot make an authorized AWS call. Recovery never exposes an IAM mutation callback.

| Window | IAM possible | Durable evidence | Recovery after authenticated expiry | Eventually release | Retry IAM |
|---|---|---|---|---|---|
| A before reservation | no | approval | no held owner; authority unused unless reservation appears | no owner | only unused authority |
| B after reservation before acquire | no | reservation | consistent row read distinguishes absent from acquired; consumed authority remains consumed | no owner if absent | no |
| C during acquire | no | reservation; atomic row may exist | read exact row/acquisition; no-write recovery if held | yes if compatible state | no |
| D after acquire before separate receipt | no | acquisition evidence is atomic with row, no separate receipt gap | acquisition + reservation + absent commit + compatible state | yes | no |
| E before authentication | no | acquired row | same no-write recovery | yes | no |
| F authentication failure | no | acquired row | same; authenticate approval at acquisition time, not mutable current time | yes if evidence authenticates | no |
| G before predecessor read | no | acquired row | compatible canonical policy/default; pruning approved exact inventory | yes | no |
| H predecessor read failure | no | acquired row | same | yes if reads become available | no |
| I before intent | no | acquired row | same, absence of commit and any intent authenticated | yes | no |
| J intent persistence uncertain | no unless commit independently exists | row; S3 intent may exist | validate present intent; absent commit prevents successor success | yes on exact no-write state | no |
| K after intent before IAM | yes if conditional commit exists, otherwise no | intent plus optional commit | exact predecessor => no-write; exact successor only if committed | yes on exact outcome | no |
| L definite IAM failure | conservatively yes | committed intent | exact predecessor => no-write; no blind error-class retry | yes on exact outcome | no |
| M uncertain IAM result | yes | committed intent | exact predecessor/successor only | yes on exact outcome | no |
| N after mutation before read | yes | committed intent | exact successor + unchanged prerequisites + required state closure | yes on exact outcome | no |
| O successor read failure | yes | committed intent | same | yes when evidence available | no |
| P before terminal receipt | yes | committed intent | independently derive exact outcome | yes on exact outcome | no |
| Q terminal receipt write uncertain | yes/no per commit | terminal may exist | authenticate/reuse immutable terminal; never replace it | yes | no |
| R before replay completion | outcome recorded | terminal | authenticate terminal then exact conditional completion | yes | no |
| S before release | outcome recorded | terminal plus DDB terminal hash | authenticate exact hash then exact release | yes | no |
| T release uncertain | outcome recorded | held/released row | consistent read; release held exact generation or observe released | yes | no |
| U after release | outcome recorded | released row | no held lock; replay reservation rejects new generation | already released | no |

Convergence successor additionally requires exact derived target policy, a single newly default version preserving every predecessor version (with only the former default flag changed), unchanged role/traffic, exact Terraform state and normal no-op policy plan. If state-only reconciliation is needed, the existing separately approved reconciliation boundary remains mandatory.
Pruning successor is exactly canonical predecessor inventory minus approved non-default target, preserving operative document/default and every other version. Exact predecessor is no-write; neither state is ambiguous. No latest or numeric successor selection is authorized.

## Durable ordering and test coverage

Reservation is an atomic S3 conditional create before DDB acquisition. Acquisition identity and metadata are one conditional DDB write; there is no separate acquisition-receipt crash gap. Intent is an immutable conditional S3 write; a conditional DDB intent-hash commit then precedes every IAM callback. Terminal receipts precede conditional completion, and completion precedes exact owner/generation release. Uncertain writes retain the row. A no-write receipt and a success receipt share one terminal slot; recovery authenticates whichever exact outcome was durably committed and never replaces it.

The deterministic ownership and native executor matrices inject failure before/after each meaningful reservation, acquisition, authentication, predecessor, intent, commit, IAM, successor, receipt, completion and release boundary for both convergence and pruning. Additional tests race recoveries and normal writers, reject identity/receipt substitutions, and revalidate consumed-approval replay and exact pruning deletion success. `node --test scripts/tests/stage-b-broker-policy-ownership.test.mjs scripts/tests/stage-b-staged-broker-executor.test.mjs` runs these checks.

A policy successor alone does not prove Terraform reconciliation. Recovery retains ownership when the normal plan still shows drift or state differs; state-only reconciliation remains a separately governed prerequisite, never a retry of IAM or an unapproved normal apply. No physical-process termination or administrator mutate-and-restore detection guarantee is made.
