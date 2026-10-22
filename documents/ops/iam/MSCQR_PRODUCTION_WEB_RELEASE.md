# Governed production web release

Production web evidence is intentionally separate from the mature four-image Stage-B object. Coordinated release consumes both authorizations and requires their exact protected `sourceSha` values to match. This preserves existing Stage-B consumers and permits web-only publication only when canonical image-impact evidence requires it.

## Publication and evidence

Dispatch `.github/workflows/production-web-image.yml` from protected `main` with only `release_sha`. Environment `production-web-image-publish` requires review by `T-ej2003`, permits that operator to approve their own deployment, and allows deployments only from protected `main`; it exposes only `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE`. GitHub OIDC is the sole credential path. Account `368992683803`, region `eu-west-2`, repository `mscqr-web`, context `.`, `Dockerfile.ecs-frontend`, platform `linux/amd64`, and the full SHA tag are fixed in source.

This environment is operator-configured, not managed by Terraform. After this contract change merges and before the next publication, configure the GitHub environment with required reviewer `T-ej2003`, self-review permitted, and protected-`main`-only deployment branches; verify those live settings before dispatch. The repository contract does not itself update GitHub environment settings.

The workflow authenticates immutable ECR configuration, publishes and reads back one digest, scans critical vulnerabilities, produces SBOM and provenance attestations, applies and verifies keyless Cosign evidence, and retains `production-web-image/web-image.jsonl` for 90 days.

`scripts/aws/production-web-release-contract.mjs` defines 24-hour schema-v1 evidence and authorization binding source, run/artifact identity, reviewer, repository, digest, platform, build identity, account/region, ECR readback, and canonical image-impact hash. `scripts/aws/produce-production-web-image-evidence.mjs` is the sole governed web-evidence producer: it starts from a clean exact protected-main checkout, authenticates the exact successful web-publication workflow run and immutable artifact archive, checks SBOM/provenance hashes and the fixed supply-chain verifier, reads back immutable ECR state, verifies the authenticated Stage-B impact is web-required, signs exactly once with the existing root-only attestation key, verifies that signature, and atomically writes evidence, signature, and authorization. A complete coordinated release therefore expects two KMS signatures: unchanged Stage-B evidence plus web evidence. Mixed-source pairs fail closed.

The evidence producer is a root-attested operator operation, not a generic signer or JSON construction step. Its fixed command is:

```sh
node scripts/aws/produce-production-web-image-evidence.mjs \
  --source-sha <exact-protected-main-sha> \
  --stage-b-authorization <private-stage-b-authorization.json> \
  --stage-b-authorization-sha256 <exact-file-sha256> \
  --web-workflow-run-id <successful-production-web-image-run-id> \
  --output-dir <new-private-0700-directory-outside-the-repository>
```

The caller cannot select a repository, Dockerfile, platform, account, region, KMS key, artifact member, or output filename. The command accepts only the canonical root-attestation profile fixed in source and refuses any workflow, source, artifact, ECR, impact, or signature mismatch before producing the authorization.

## Activation and rollback

The release deployer captures stable `mscqr-frontend-servi-euw2`, derives `mscqr-frontend` registration input from its current task definition, and changes only `frontend.image` to the authenticated digest. AWS-normalized registration readback must equal the candidate. Immediately before one `UpdateService`, task definition, opaque PRIMARY deployment ID, image, desired count, and 2/2/0 state must still equal the predecessor.

After a historical rotation-overlap backend release, the standalone protected `production-web-activation.yml` can activate an already signed, web-required image release. Supply the matching Stage-B and web authorizations for that image release plus the exact successful overlap Release Gate run/attempt, original rotation release SHA, and rotation ID. The overlap release must be an authenticated Git ancestor of the signed frontend target; a later backend release cannot authorize an older frontend merely because its image digest matches. The runner independently resolves the protected production approval and immutable overlap receipt, requires its backend digest to match the signed Stage-B image, then checks the live backend task definition, two running tasks, digest, and ready endpoint before the frontend update. This path does not create normal-backend activation evidence or replay the Full-RLS release. The original rotation release, immutable image release, and current protected execution source retain distinct identities; the four overlap inputs are forbidden with normal-backend activation evidence.

Registration failure performs no service update. Update, stabilization, `/login`, or health failure may roll back only to the exact captured predecessor while the service still points at the failed candidate. Arbitrary service, family, image, or rollback inputs are rejected.

AWS IAM cannot resource-scope or field-constrain `ecs:RegisterTaskDefinition`. The release role therefore uses the AWS-supported wildcard resource for that API only. The security boundary is the isolated release principal, fixed source constructor, exact `iam:PassRole` closure, full AWS-materialized readback, and exact service/predecessor CAS; callers cannot supply task fields.

## Terraform state and publisher provisioning

The `infra/aws/terraform/production-web-release` root is the canonical desired-state owner for the publisher role, its boundary and permissions policy, and the narrowly scoped `MSCQRProductionFrontendActivation` inline policy on the existing `mscqr-production-release-deployer` role. Its IAM resource mutations are bootstrapped only by `scripts/aws/bootstrap-production-web-release-iam.mjs`, which reads those exact documents and accepts only the production account root configuration profile. Ordinary bootstrap creates absent resources and fails closed on a non-identical existing object; the separately reviewed CHG-20261022-001 transition below permits exactly one recorded frontend predecessor update and one native-audit creation. Terraform imports the resulting objects into its dedicated state and detects drift; the operator has no IAM mutation permissions.

An MFA-backed, non-root production operator must use the dedicated encrypted production S3 state and S3 lockfile. AWS root must not plan or apply:

```sh
# Refuse to hide any prior local state; its ownership must be resolved first.
for state_path in infra/aws/terraform/production-web-release/terraform.tfstate infra/aws/terraform/production-web-release/terraform.tfstate.backup infra/aws/terraform/production-web-release/terraform.tfstate.d; do
  if [ -e "$state_path" ]; then echo "Unexpected local Terraform state: $state_path" >&2; exit 1; fi
done
# Isolate backend metadata from any previous local or alternate-backend init.
TF_DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mscqr-web-release-tfdata.XXXXXX")"
chmod 700 "$TF_DATA_DIR"
export TF_DATA_DIR
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release init \
  -upgrade=false -input=false \
  -backend-config='bucket=mscqr-production-terraform-state-368992683803-eu-west-2' \
  -backend-config='key=mscqr/production/web-release/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
test "$(TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release workspace show)" = default
aws sts get-caller-identity
```

The one-time exact-source IAM bootstrap must run from a clean protected-main checkout before Terraform import. It is an exact-document executor, not Terraform and not a manual IAM edit. It creates only the four absent source-defined objects; an existing object is accepted only when its identity and policy/trust document match source exactly:

```sh
node scripts/aws/bootstrap-production-web-release-iam.mjs \
  --source-sha <exact-protected-main-sha> \
  --admin-profile mscqr-production-root
```

The operator policy reconciliation grants the MFA-backed non-root operator only the exact state/lock access and read access to the publisher role, release-deployer role, and publisher boundary required to import and plan. Its inline policy remains within IAM's 2,048-character quota and grants no IAM create, update, attach, pass-role, trust-policy, or delete action. Verify the caller is in account `368992683803` under the approved non-root operator identity.

Use these exact Terraform imports after the source bootstrap and backend initialization. On a resumed partial import, first inspect `terraform state list`; skip an address only when `terraform state show` confirms its `id` is exactly the corresponding identifier below. Import only absent addresses. Stop if an address is bound to any other identifier or the state cannot be read; never remove or overwrite state to retry:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import aws_iam_policy.publisher_boundary arn:aws:iam::368992683803:policy/MSCQRProductionWebImagePublisherBoundary
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import aws_iam_role.publisher mscqr-production-web-image-publisher
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import aws_iam_role_policy.publisher mscqr-production-web-image-publisher:MSCQRProductionWebImagePublisher
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import aws_iam_role_policy.frontend_activation mscqr-production-release-deployer:MSCQRProductionFrontendActivation
```

Import every object before planning. A plan created before an import must be discarded and recreated. Generate a fresh plan only after every import, and require it to be a no-op. The imported plan must be a no-op; any IAM update, delete, or replacement is a stop condition because the non-root operator cannot mutate IAM. Apply only the reviewed no-op saved plan:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release plan -out=web-release.tfplan
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release apply web-release.tfplan
```

Read back the publisher trust/policy and boundary, then set `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE` on the protected `production-web-image-publish` environment to the Terraform `publisher_role_arn` output. A later approved IAM-document change must add its exact live predecessor to the source bootstrap before it can converge; the bootstrap never overwrites unknown drift.

## CHG-20261022-001 exact IAM reconciliation

The Phase 3 transition is deliberately narrower than a general IAM update. The reviewed source bootstrap accepts only the recorded live frontend policy fingerprint `a43a0e5e579f91e6dd1da3005de72984becc28e86f9d316a87b8001164dc6352`, target frontend fingerprint `5f594748ad6f60ec039a2c2a1ef3744cb28c857732fdd427acb7baaad5a7c93d`, and new native audit fingerprint `741f2c3e88478ad23d287f58298cc1abbd3ef6f8459cd29aa20b1f202c5a5122`. It binds ticket `CHG-20261022-001`, account `368992683803`, region `eu-west-2`, the release-deployer role, and both exact inline-policy names. There is no external or AWS requirement for a second human IAM reviewer. PR #721 merged without its required pre-merge V1 comment, so V1 cannot authorize execution. The correction permits only a fresh V2 comment on the correction PR **after that PR merges**, with both PR identities checked. The accountable operator must inspect the exact transition and post this unedited comment on the correction PR, replacing both placeholders with its final reviewed head and merge SHA:

```text
MSCQR_PHASE3_IAM_SOLO_AUTH_V2:751eddd0f16312f7592091542d1dea23d701cd1e571fead3b4e124bc7de167cc:<correction_pr_head_sha>:<correction_merge_sha>
```

The V2 digest binds PR #721's reviewed head `503460a5d7eeda19bf66f7782bbefe34f5524fdf`, its merge `0237d3f24afe5e3af5efbf26e5176edc8db81fc4`, ticket, account, region, policy names, and all predecessor/target fingerprints. The installer independently reads both PRs from pinned `github.com`, requires the correction PR to be based directly on PR #721's merge and merged as the current protected-main source, and verifies the protected-main ancestry. It requires the unedited comment from GitHub user `T-ej2003` (ID `183396573`) to have been created after the correction PR merged and within the last two hours. It checks the comment again after interactive MFA, before ownership and after each dispatch journal immediately before the corresponding IAM write. A missing, edited, expired, duplicate, or wrong-source comment stops any pending IAM write. An expired comment can be replaced before any ownership claim; a claimed operation cannot be rebound to a different comment and requires separate reviewed recovery if it expires. Codex's automated review is defect evidence, never a human approval. The existing component-IAM approval workflow is scoped to other documents and cannot authorize this transition. This solo IAM authorization does not enable the disabled Stage B conditional lane or change root, checker, or verifier approval rules.

After the correction PR merges, treat its new protected-main SHA as a **new release source**; do not rebind older image or Stage B approvals. Generate a fresh private Terraform plan with the existing MFA-backed non-root profile and the production-web-release backend, binding the exact merged protected-main SHA:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release plan \
  -var="phase3_iam_source_sha=<new_protected_main_sha>" \
  -out=<private_saved_plan>
```

The installer rejects a plan with an absent or different `phase3_iam_source_sha` before acquiring mutation ownership. Confirm only the two permitted transitions are present. Keep its saved binary outside the repository and record its SHA-256. Do not apply this plan; the exact-document bootstrap is the IAM writer. Preserve the same initialized private `TF_DATA_DIR` in the trusted terminal for the installer's read-only `terraform show`; the plan cannot be decoded without its provider schema. The installer uses only a safelisted Terraform binary and a sanitized subprocess environment, and decodes a private copy of the exact bytes whose SHA-256 it records.

On the trusted terminal, keep the owner file in a private mode-0700 directory outside the repository. After the post-merge V2 operator comment, clean Codex review, passing required CI, protected-main merge, and fresh-plan review, run the source-controlled installer from a clean exact-main checkout with the governed root configuration profile. The command prompts for the bootstrap operator's MFA code, obtains a fresh 900-second STS session with the fixed MFA serial, and verifies the exact non-root IAM user. The AWS CLI challenge is held briefly in a mode-0600 file under a mode-0700 temporary directory and removed immediately after issuance; credentials and the code never go to GitHub or logs:

```sh
node scripts/aws/bootstrap-production-web-release-iam.mjs \
  --source-sha <new_protected_main_sha> \
  --admin-profile mscqr-production-root \
  --ticket-id CHG-20261022-001 \
  --authorization-pr <solo_authorized_correction_pr> \
  --plan-file <private_saved_plan> \
  --owner-file <private_directory>/phase3-iam-owner.json
```

The installer authenticates exact account root, the operator comment, fresh MFA session, source policy fingerprints, plan semantics, live predecessor, and a write-once S3 ownership claim before any IAM write. The frontend plan action must match its live checkpoint: predecessor requires update and target requires no-op. An absent audit policy requires create; an already installed audit target permits create while it remains unimported in Terraform state, or no-op after import. Never apply a recovery plan that still shows create; import the authenticated audit target only after IAM reconciliation completes. A partial or completed checkpoint also requires the original private owner file, matching encrypted S3 claim, and exact dispatch markers before any continuation. The installer reads protected main through the pinned, authenticated GitHub API after interactive MFA, immediately before ownership, before each IAM journal and again after each journal; source advancement stops the transition. It never trusts a locally redirected Git transport for protected-main freshness. It also rechecks both live policies before dispatch. The initial MFA proof metadata is retained in the encrypted claim; credentials and MFA code are not. Each policy receives a separate encrypted write-ahead dispatch marker with a unique attempt ID before `PutRolePolicy`; if its first S3 response is lost, exact readback of that attempt ID permits this invocation to continue, while another invocation cannot consume the marker. The safelisted AWS CLI subprocess uses one attempt for every IAM write and conditional S3 journal write. A target appearing between checkpoint and installation is accepted only with this owner's matching dispatch marker. The policy predecessor is read again after the marker is durable and immediately before `PutRolePolicy`; drift stops the write. The installer installs the native audit policy first, then the frontend policy, with exact readback after each, and publishes an encrypted write-once completion receipt. A lost IAM response is reused only when live policy equals the target. If a dispatch marker exists but live IAM remains at the predecessor, outcome is unknown and the installer stops instead of issuing a duplicate write. Retain the owner file for interrupted recovery; another owner cannot claim this operation. A restart requires a new MFA challenge and a fresh plan for the observed checkpoint. Unexpected drift or an unknown write outcome stops.

After live readback, import only the new inline policy into the existing remote Terraform state using the MFA-backed non-root operator:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import \
  aws_iam_role_policy.stage_b_native_audit \
  mscqr-production-release-deployer:MSCQRProductionStageBNativeAudit
```

Then produce a fresh plan and require **zero changes**. Verify live policy fingerprints and IAM simulation of the required reads and forbidden writes before Stage B root issuance. Never run Terraform plan/apply as root or edit IAM directly.

## Governed operator sequence

1. Merge reviewed source and derive exact image impact.
2. Publish/authenticate four Stage-B images when required.
3. Separately publish/authenticate web when required.
4. Run the fixed governed web-evidence producer above; it KMS-signs web evidence once and generates the web authorization atomically.
5. Verify one source SHA across Stage-B, web, DB package, backend, and frontend candidates.
6. Verify the database before backend activation.
7. Activate backend, then frontend under exact predecessor CAS.
8. Verify health and G06/G11 behavior; run controlled physical-printer acceptance separately.

Adding this contract performs no publication, signing, IAM application, ECS update, or production mutation.
