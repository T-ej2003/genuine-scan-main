import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonical } from "./component-iam-installation-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const prefix = "mscqr/production/component-deployment-state/";

export const brokerRecoverySuccessorEvidenceReader = Object.freeze({
  roleName: "mscqr-production-broker-recovery-successor-evidence-reader",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-broker-recovery-successor-evidence-reader",
  policyName: "MSCQRProductionBrokerRecoverySuccessorEvidenceRead",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionBrokerRecoverySuccessorEvidenceRead",
  environment: "production-component-broker-recovery-successor-evidence",
  workflow: ".github/workflows/authorize-component-broker-recovery-successor.yml",
  trustPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/broker-recovery-successor-evidence-reader-trust-policy.json",
  permissionsPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/broker-recovery-successor-evidence-reader-permissions-policy.json",
  description: "Temporary GitHub OIDC reader for exact broker successor lineage evidence.",
  policyDescription: "Read only the two immutable component broker successor lineage objects.",
  tags: Object.freeze({ ManagedBy: "Terraform", Environment: "production", Component: "broker-recovery-successor-evidence", Stack: "production-initial-activation-policy-reconciler" }),
  resources: Object.freeze([
    `arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/${prefix}broker-policy-successor.json`,
    `arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/${prefix}identity-bootstrap.json`,
  ]),
});

const sourceJson = relative => JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));

export function assertBrokerRecoverySuccessorEvidenceReaderSource() {
  const trust = sourceJson(brokerRecoverySuccessorEvidenceReader.trustPath), permissions = sourceJson(brokerRecoverySuccessorEvidenceReader.permissionsPath);
  assert.deepEqual(trust, { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" }, Action: "sts:AssumeRoleWithWebIdentity", Condition: { StringEquals: {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": `repo:T-ej2003/genuine-scan-main:environment:${brokerRecoverySuccessorEvidenceReader.environment}`,
    "token.actions.githubusercontent.com:repository_owner_id": "183396573",
    "token.actions.githubusercontent.com:repository_id": "1145608538",
    "token.actions.githubusercontent.com:actor_id": "183396573",
    "token.actions.githubusercontent.com:ref": "refs/heads/main",
    "token.actions.githubusercontent.com:job_workflow_ref": `T-ej2003/genuine-scan-main/${brokerRecoverySuccessorEvidenceReader.workflow}@refs/heads/main`,
  } } }] });
  assert.deepEqual(permissions, { Version: "2012-10-17", Statement: [{ Sid: "ReadExactHistoricalBrokerSuccessorEvidence", Effect: "Allow", Action: "s3:GetObject", Resource: brokerRecoverySuccessorEvidenceReader.resources }] });
  assert(!/\*/.test(canonical(permissions)), "Evidence-reader wildcard forbidden");
  return Object.freeze({ trust, permissions });
}

export const brokerRecoverySuccessorEvidenceReaderRetirement = Object.freeze({
  requiresSecondSuccessorState: "BROKER_RECOVERY_SUCCESSOR_CLOSED",
  requiresPartialActivationRecoveryState: "RECOVERY_CLOSED",
  automatic: false,
  deletionRequiresFreshProtectedSourceAndExactPlan: true,
});
