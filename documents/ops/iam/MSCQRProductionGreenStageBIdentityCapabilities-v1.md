# Stage B production identity capability boundary

The machine authority is `MSCQRProductionGreenStageBIdentityCapabilities-v1.json`; Terraform actions and resources remain authoritative in `MSCQRProductionGreenStageBPermissionManifest-v1.json`.

Administrator/root owns ECR evidence reads, IAM policy inspection and simulation, CloudTrail denial inspection, and KMS signing. The release-deployer owns direct safe discovery reads, backend/state access, refresh, reference audit, saved-plan apply, and KMS verification. The release-deployer must never call `iam:SimulatePrincipalPolicy` or `cloudtrail:LookupEvents`.

Run the same command in two explicit identity sections. Root first creates the signed pre-plan capability report:

`npm run stage-b:production-preflight -- --identity administrator --output /private/tmp/stage-b-admin-preflight.json --signature-output /private/tmp/stage-b-admin-preflight.signature.json`

The release-deployer then consumes it and supplies the existing canonical backend, tooling, image, broker, handoff, and tfvars options. The release section attempts every independent safe read and reports all denials together. It cannot initialize the backend unless the signed administrator report and every direct read are valid. Mutation denial and apply capability remain administrator-simulated by `validate-production-green-stage-b-permissions.mjs`; mutation APIs are never used as probes.
