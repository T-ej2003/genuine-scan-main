#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "./aws/production-green-stage-b-contract.mjs";
import { assertInitialActivationCompletionAbsent, createProductionInitialActivationAws, readInitialActivationClaim } from "./aws/production-initial-activation-lifecycle.mjs";
import { PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./aws/production-credential-source-contract.mjs";
import { validateProductionInitialActivationDuringAuthenticatedOverlap } from "./security/production-initial-overlap-activation-contract.mjs";

const names = ["STATE_FILE", "STATE_SHA256", "SOURCE_SHA", "ROTATION_ID", "DEPLOYMENT_SHA", "TASK_DEFINITION", "ACTIVATION_TASK_DEFINITION", "IMAGE_DIGEST", "CLAIM_SHA256", "ACTIVATION_TRANSACTION_ID"];

export async function checkProductionActivationRotation({ env = process.env, readClaim = readInitialActivationClaim, assertCompletionAbsent = assertInitialActivationCompletionAbsent, createAws = createProductionInitialActivationAws, validateOverlap = validateProductionInitialActivationDuringAuthenticatedOverlap, validateFinal } = {}) {
  const values = Object.fromEntries(names.map((name) => [name, env[`PRODUCTION_INITIAL_OVERLAP_${name}`]]));
  const contract = env.PRODUCTION_ACTIVATION_ROTATION_CONTRACT;
  if (contract === "STRICT_FINAL_ROTATION") {
    if (Object.values(values).some((value) => value)) throw new Error("Strict final rotation cannot consume initial-overlap bindings.");
    if (validateFinal) await validateFinal();
    else await import("./check-rotation-evidence-freshness.mjs");
  } else if (contract === "AUTHENTICATED_OVERLAP") {
    if (Object.values(values).some((value) => !value)) throw new Error("Initial-overlap activation bindings are incomplete.");
    const aws = createAws({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env });
    assertCompletionAbsent({ aws });
    const claim = readClaim({ aws, expected: {
      sourceSha: values.SOURCE_SHA, rotationId: values.ROTATION_ID, overlapDeploymentSha: values.DEPLOYMENT_SHA,
      taskDefinitionArn: values.TASK_DEFINITION, activationTaskDefinitionArn: values.ACTIVATION_TASK_DEFINITION,
      imageDigest: values.IMAGE_DIGEST, activationTransactionId: values.ACTIVATION_TRANSACTION_ID,
    } });
    if (claim.sha256 !== values.CLAIM_SHA256) throw new Error("Production initial activation claim digest changed.");
    return validateOverlap({
      rawState: readFileSync(values.STATE_FILE), stateSha256: values.STATE_SHA256,
      claimRaw: Buffer.from(`${canonicalJson(claim.value)}\n`), claimSha256: claim.sha256,
      expected: { sourceSha: values.SOURCE_SHA, rotationId: values.ROTATION_ID, deploymentSha: values.DEPLOYMENT_SHA, taskDefinitionArn: values.TASK_DEFINITION, imageDigest: values.IMAGE_DIGEST },
    });
  } else throw new Error("Production activation rotation contract must be selected explicitly.");
  return { contract };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  checkProductionActivationRotation().then((result) => process.stdout.write(`${result?.contract || "STRICT_FINAL_ROTATION"}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
