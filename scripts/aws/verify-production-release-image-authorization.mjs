#!/usr/bin/env node
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { assertImageAuthorization } from "./production-cutover-control-plane.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";
import { WEB_RELEASE, captureFrontendPredecessor } from "./production-web-release-contract.mjs";

const repositories = { backend: "mscqr-backend", worker: "mscqr-worker", "rls-executor": "mscqr-backend", "rls-canary": "mscqr-backend" };

export function verifyProductionReleaseImageAuthorization({ authorization, sourceSha, verifyImageEvidence, now, minimumRemainingMs } = {}) {
  assertImageAuthorization(authorization, sourceSha, { verifyImageEvidence, now, minimumRemainingMs });
  return Object.freeze(Object.fromEntries(authorization.images.map(({ service, digest }) => [service, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repositories[service]}@${digest}`])));
}

export function createReleaseGateImageAuthorizationRunner({ env = process.env, exec } = {}) {
  return createProductionCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,
    env,
    ...(exec ? { exec } : {}),
  });
}

export function frontendActivationRequired({ sourceSha, repository, images, service, taskDefinition }) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || repository?.repositoryName !== WEB_RELEASE.repository
      || String(repository.registryId) !== WEB_RELEASE.account || repository.imageTagMutability !== "IMMUTABLE"
      || repository.imageTagMutabilityExclusionFilters?.length) throw new Error("Current-source web repository identity is invalid.");
  if (!Array.isArray(images) || images.length !== 1 || !/^sha256:[a-f0-9]{64}$/.test(images[0]?.imageDigest || "")
      || !images[0].imageTags?.includes(sourceSha)) throw new Error("Current-source web image is absent or ambiguous.");
  const predecessor = captureFrontendPredecessor(service, taskDefinition);
  return predecessor.imageRef !== `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@${images[0].imageDigest}`;
}

export function runCli(argv = process.argv.slice(2)) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!new Set(["--source-sha", "--authorization", "--authorization-sha256", "--github-output", "--credential-source"]).has(key) || !value || value.startsWith("--") || args.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    args.set(key, value);
  }
  const required = (name) => { const value = args.get(name); if (!value) throw new Error(`${name} is required.`); return value; };
  const authorization = readBoundStageBPrivateJson({ filePath: required("--authorization"), expectedSha256: required("--authorization-sha256"), label: "Normal release image authorization" });
  if (required("--credential-source") !== PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER) throw new Error("Release-gate image authorization requires the GitHub OIDC release-deployer credential source.");
  const releaseRun = createReleaseGateImageAuthorizationRunner();
  const refs = verifyProductionReleaseImageAuthorization({ authorization, sourceSha: required("--source-sha"), verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: releaseRun }) });
  const read = (args) => JSON.parse(releaseRun([...args, "--output", "json", "--no-cli-pager"]));
  const service = read(["ecs", "describe-services", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]);
  if (service.failures?.length || service.services?.length !== 1) throw new Error("Frontend service readback is incomplete.");
  const definition = read(["ecs", "describe-task-definition", "--task-definition", service.services[0].taskDefinition]).taskDefinition;
  const repository = read(["ecr", "describe-repositories", "--repository-names", WEB_RELEASE.repository]).repositories?.[0];
  const images = read(["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageTag=${required("--source-sha")}`]).imageDetails;
  const requiredActivation = frontendActivationRequired({ sourceSha: required("--source-sha"), repository, images, service: service.services[0], taskDefinition: definition });
  fs.appendFileSync(required("--github-output"), `${Object.entries(refs).map(([service, ref]) => `${service.replaceAll("-", "_")}_image_ref=${ref}\n`).join("")}image_release_sha=${authorization.imageReleaseSha}\nweb_required=${authorization.imageReuseEvidence.webPublicationRequired || requiredActivation}\n`);
  return refs;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
