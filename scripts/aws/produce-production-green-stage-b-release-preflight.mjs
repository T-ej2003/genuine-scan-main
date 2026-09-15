#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runReleaseReadPreflight } from "./production-green-stage-b-identity-capabilities.mjs";
import { readBoundStageBPrivateJson, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout, assertStageBProtectedCheckoutMatchesDeploymentIdentity } from "./stage-b-deployment-identity.mjs";
import { verifyProductionReleaseImageAuthorization } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function produceStageBReleasePreflight(argv = process.argv.slice(2), dependencies = {}) {
  const allowed = new Set(["--source-sha", "--image-authorization", "--image-authorization-sha256", "--tfvars-sha256", "--binding-sha256", "--output"]);
  if (argv.length % 2 || argv.some((value, index) => index % 2 === 0 && !allowed.has(value)) || new Set(argv.filter((_, index) => index % 2 === 0)).size !== argv.length / 2) throw new Error("Stage B release preflight producer arguments are not exact.");
  const sourceSha = required(argv, "--source-sha"); const imagePath = required(argv, "--image-authorization"); const imageSha = required(argv, "--image-authorization-sha256"); const tfvarsSha256 = required(argv, "--tfvars-sha256"); const bindingSha256 = required(argv, "--binding-sha256"); const output = path.resolve(required(argv, "--output"));
  if (!SHA40.test(sourceSha) || !SHA256.test(imageSha) || !SHA256.test(tfvarsSha256) || !SHA256.test(bindingSha256)) throw new Error("Stage B release preflight producer identity is malformed.");
  const checkout = (dependencies.readProtectedMainCheckout || (() => readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true })))();
  (dependencies.assertProtectedCheckout || assertStageBProtectedCheckoutMatchesDeploymentIdentity)({ protectedMainCheckout: checkout, deploymentIdentity: { toolingSha: sourceSha } });
  const releaseRun = dependencies.releaseRun || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env: dependencies.env || process.env });
  const authorization = dependencies.readAuthorization
    ? dependencies.readAuthorization(imagePath, imageSha, sourceSha)
    : readBoundStageBPrivateJson({ filePath: imagePath, expectedSha256: imageSha, repositoryRoot: root, label: "Release image authorization" });
  (dependencies.verifyAuthorization || verifyProductionReleaseImageAuthorization)({
    authorization,
    sourceSha,
    verifyImageEvidence: (options) => (dependencies.verifyImageEvidence || verifyImageEvidenceSignature)({ ...options, run: releaseRun }),
  });
  const report = (dependencies.runReleaseReadPreflight || runReleaseReadPreflight)({
    outputDirectory: path.dirname(output),
    run: releaseRun,
    authenticatedImageAuthorization: authorization,
  });
  if (report.status !== "valid") throw new Error("Stage B release preflight read probes are not valid.");
  const document = { ...report, sourceSha, tfvarsSha256, bindingReportSha256: bindingSha256, status: "ready-for-plan", stageAStateIdentityPath: null };
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, normalize: true });
  const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
  const written = writeStageBPrivateFileAtomic({ filePath: output, bytes, repositoryRoot: root, label: "Stage B release preflight" });
  return { status: document.status, report: written, reportSha256: sha256(bytes) };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(produceStageBReleasePreflight())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
