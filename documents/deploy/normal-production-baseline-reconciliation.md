# Normal production baseline reconciliation

Protected-main reference: `dc7623302ddbfe4f92108a1f6e4b2fed43d8ac39`.

## Objective

Allow an eligible backend-only application push to use the existing normal deployment workflow while retaining the older frontend baseline and its undeployed changes. No historical deployment is inferred from a merged commit.

## Authenticated starting point

The strongly consistent production component-state readback is generation 2. Backend task definition `mscqr-production-rls-green-backend-candidate:37` is bound to source `d785aa7f1e154f37c0dc621082e3f6c46d5d5aec` by historical-completion run `40301022385`. Frontend task definition `mscqr-frontend:22` remains bound to `b7e0f171c716d5ba6d5a13da096bd87d9b638867` by bootstrap run `37054699578`. The only completed emergency marker is backend-health-recovery. There is no pending normal release receipt.

The current frontend source range includes later STARtex auth/API changes. No authenticated frontend deployment receipt for those changes was found. They remain pending and cannot enter the normal lane. The backend range since its deployed source contains control-plane, test, and RLS-executor inputs, but no changed backend runtime input. The fixture in `scripts/tests/fixtures/production-normal-generation2.json` records the exact state and source ranges used for regression tests.

## Correction

The protected-main push still determines normal-lane eligibility. Preparation now considers accumulated changes only for components selected by that push. For a selected component it evaluates its production image inputs since the authenticated component-state source. A security-sensitive or unknown selected image input still fails closed. Unselected components keep their prior state and their pending source ranges for a future governed release. Existing recovery completion filtering, live ECS verification, ECR protection, image authorization, receipt reconciliation, rollback, and DynamoDB compare-and-swap remain in place.

No component-state advancement is performed by preparation. No new historical-completion mechanism is added because the outstanding frontend work has no authenticated deployment completion to adopt.

## Hostile review

The first input map missed verifier scripts copied into the backend runtime stage; the final map includes them, and a Docker `COPY` contract test fails if a future direct input is omitted. A push that touches auth, schema, worker, infrastructure, or an unknown path still fails the normal lane. A selected component's accumulated sensitive runtime input fails preparation. An unselected component retains its old state and is reverified live by the existing transaction. Existing tests cover wrong image identity, denied ECR protection, partial ECS mutation, rollback, receipt reconciliation, health failure, and generation conflicts. No AWS or component-state write is performed by this correction.

## Acceptance and operational limit

An eligible backend-only push must prepare a backend-only transaction from generation 2. A frontend push must reject the undeployed sensitive frontend range until a governed stronger-lane release authenticates and deploys it. The current production ECR repository-protection check is a separate enforced prerequisite: backend/web lifecycle policies and repository guards must satisfy it before any normal image can be published. A successful source test or PR does not establish live deployment readiness.
