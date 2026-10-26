# Normal production baseline reconciliation

Protected-main reference: `dc7623302ddbfe4f92108a1f6e4b2fed43d8ac39`.

## Objective

Prepare eligible application pushes from component-specific sources without treating a merged commit as proof of deployment or of privileged tooling authorization.

## Authenticated starting point

The strongly consistent production component-state readback is generation 2. Backend task definition `mscqr-production-rls-green-backend-candidate:37` is bound to source `d785aa7f1e154f37c0dc621082e3f6c46d5d5aec` by historical-completion run `40301022385`. Frontend task definition `mscqr-frontend:22` remains bound to `b7e0f171c716d5ba6d5a13da096bd87d9b638867` by bootstrap run `37054699578`. The only completed emergency marker is backend-health-recovery. There is no pending normal release receipt.

The current frontend source range includes later STARtex auth/API changes. No authenticated frontend deployment receipt for those changes was found. They remain pending and cannot enter the normal lane. The backend range since its deployed source contains control-plane, test, and RLS-executor inputs, but no changed backend runtime input. The fixture in `scripts/tests/fixtures/production-normal-generation2.json` records the exact state and source ranges used for regression tests.

## Correction

The protected-main push still determines normal-lane eligibility. Preparation considers accumulated changes only for components selected by that push. It retains both sides of renames and copies and rejects historical additions or deletions of selected image inputs unless they belong to the current eligible push. Sensitive runtime inputs remain pending until their own deployment evidence advances that component. Unselected components keep their prior state.

Privileged workflow and host-executed tooling changes cannot be silently discarded. The planner accepts historical tooling only when the existing security component state records a later `SECURITY_INFRASTRUCTURE` Release Gate completion with an exact source and authorization identity, and no tooling edit follows that source. A tooling file copied into a selected runtime image still requires that component's deployment evidence. The preparation and execution state hashes bind the authorization through the transaction. The job checks its checkout before OIDC; that check alone does not authenticate a changed workflow. Existing recovery filtering, live ECS verification, ECR protection, image authorization, receipt reconciliation, rollback, and DynamoDB compare-and-swap remain in place.

No component-state advancement is performed by preparation. No new historical-completion mechanism is added because the outstanding frontend work has no authenticated deployment completion to adopt.

## Hostile review

Review found that an earlier script-tree hash was declared by the same workflow it purported to authenticate, and omitted the workflow YAML itself. That hash is removed. The planner now fails closed on pending privileged workflow or tooling changes. Real Git tests cover rename, copy, cross-component move, and deletion identities. A Docker `COPY` contract test covers image inputs. The existing transaction tests cover wrong image identity, denied ECR protection, partial ECS mutation, rollback, receipt reconciliation, health failure, and generation conflicts. No AWS or component-state write is performed by this correction.

## Acceptance and operational limit

The live generation-2 state has no security component completion for the accumulated workflow/tooling changes, so an application push remains blocked until the existing stronger Release Gate records that authorization. An authorized synthetic state prepares backend-only, frontend-only, and combined ordinary releases; the actual frontend remains blocked by undeployed STARtex auth/API code until its own authenticated deployment. The ECR repository-protection check is a separate enforced prerequisite.

The remaining execution-identity boundary is external to the planner: the live normal-deployer OIDC trust checks the `production-normal-deploy` environment subject but does not bind the workflow revision. The environment currently allows self review, and protected main requires zero approving PR reviews. Therefore an altered workflow can skip its own source checks. Independently enforced workflow identity or governance is required before claiming the P1 workflow-trust finding closed. No normal production deployment is claimed restored.
