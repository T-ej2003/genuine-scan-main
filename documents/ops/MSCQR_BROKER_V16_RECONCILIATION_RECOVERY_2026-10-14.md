# Broker v16 reconciliation recovery

Release Train run 38530598661, attempt 3, stopped while re-reading an authorized Terraform refresh. The native `STATE_REFRESH_INTENT`, `RECONCILED_PENDING_RELEASE_CAS`, and terminal broker handoff receipts are present. The reviewed alias is v16 and Terraform is at serial 132. The release coordinator has not saved `closure:result` or its terminal Stage B prerequisite receipt.

The recovery caller permits `RECONCILIATION_RECOVERY` to capture a normal, read-only Terraform plan, but the shared plan capture guard rejected that phase before running the plan. This correction admits that one phase to the existing plan capture path. It does not authorize Terraform apply, broker publication, alias update, or a new approval. The recovery path must authenticate the original intent, authorization, native result, live alias, Terraform state, and no-op closure plan before the coordinator records completion.

Resume only through the governed coordinator after this correction is merged and the source and change-ticket bindings are renewed. Do not rerun the completed broker, IAM, or ECS writes. Stage B and Release Gate remain incomplete until the coordinator authenticates the closure result and writes its terminal prerequisite receipt.
