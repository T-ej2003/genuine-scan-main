import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { identityBootstrap } from "./component-installation-identity-contract.mjs";
import { installationIdentity } from "./component-iam-installation-contract.mjs";

const predecessor = JSON.parse(fs.readFileSync(fileURLToPath(new URL("../../documents/ops/iam/MSCQRProductionStateBucketSignerLedgerPredecessor-v1.json", import.meta.url)), "utf8"));
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
const canonical = value => JSON.stringify(sort(value));
export const policySha256 = value => crypto.createHash("sha256").update(canonical(value)).digest("hex");
export const signerLedgerAbsence = Object.freeze({
  bucket: identityBootstrap.bucket,
  key: `${identityBootstrap.prefix}signer-policy-transition.json`,
  principal: `arn:aws:iam::${identityBootstrap.account}:role/${installationIdentity.provisionerRole}`,
  action: "s3:ListBucket",
});
const statement = Object.freeze({
  Sid: "AllowComponentBrokerListExactSignerLedger",
  Effect: "Allow",
  Principal: { AWS: signerLedgerAbsence.principal },
  Action: signerLedgerAbsence.action,
  Resource: `arn:aws:s3:::${signerLedgerAbsence.bucket}`,
  Condition: { StringEquals: { "s3:prefix": signerLedgerAbsence.key } },
});

export const signerLedgerBucketPolicyPredecessor = () => structuredClone(predecessor);
export const signerLedgerBucketPolicySuccessor = () => ({ ...structuredClone(predecessor), Statement: [...structuredClone(predecessor.Statement), structuredClone(statement)] });

export function classifySignerLedgerBucketPolicy(live) {
  assert(live && typeof live === "object", "Signer ledger bucket policy is absent");
  if (canonical(live) === canonical(predecessor)) return "EXACT_PREDECESSOR";
  if (canonical(live) === canonical(signerLedgerBucketPolicySuccessor())) return "EXACT_SUCCESSOR";
  throw new Error("Signer ledger bucket policy differs from both authenticated states");
}
