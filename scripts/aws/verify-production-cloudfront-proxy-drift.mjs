#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { collectStageBBackendProxyTrust } from "./generate-production-green-stage-a-prerequisites.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { NORMAL_ACTIVATION } from "./production-normal-backend-activation-policy.mjs";

const json = (run, args) => JSON.parse(run([...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"]));
const env = (definition) => Object.fromEntries((definition?.containerDefinitions || []).find(({ name }) => name === NORMAL_ACTIVATION.container)?.environment?.map(({ name, value }) => [name, value]) || []);
const csv = (value) => String(value || "").split(",").filter(Boolean).sort().join(",");

export function verifyProductionCloudFrontProxyDrift({ run } = {}) {
  if (typeof run !== "function") throw new Error("Production CloudFront proxy drift verification requires an authenticated AWS command runner.");
  const service = json(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.clusterArn, "--services", NORMAL_ACTIVATION.serviceArn]).services?.[0];
  if (!service?.taskDefinition) throw new Error("Production backend service is unavailable for CloudFront proxy drift verification.");
  const definition = json(run, ["ecs", "describe-task-definition", "--task-definition", service.taskDefinition]).taskDefinition;
  const actual = env(definition);
  const observed = collectStageBBackendProxyTrust({ run });
  const expected = {
    CLIENT_IP_TRUST_MODE: observed.mode,
    CLIENT_IP_TRUSTED_ALB_CIDRS: observed.alb.cidrs.join(","),
    CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS: observed.cloudFront.cidrs.join(","),
    MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_ID: observed.cloudFront.managedPrefixListId,
    MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_VERSION: String(observed.cloudFront.managedPrefixListVersion),
  };
  if (actual.CLIENT_IP_TRUST_MODE !== expected.CLIENT_IP_TRUST_MODE || csv(actual.CLIENT_IP_TRUSTED_ALB_CIDRS) !== expected.CLIENT_IP_TRUSTED_ALB_CIDRS || csv(actual.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS) !== expected.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS || actual.MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_ID !== expected.MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_ID || actual.MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_VERSION !== expected.MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_VERSION) throw new Error("Production CloudFront proxy topology or managed prefix-list drift detected. Collect fresh Stage-A prerequisites and use the governed Stage-B replacement/activation path; this verifier performs no mutation.");
  return Object.freeze({ status: "CURRENT", serviceTaskDefinition: service.taskDefinition, distributionId: observed.cloudFront.distributionId, prefixListId: observed.cloudFront.managedPrefixListId, prefixListVersion: observed.cloudFront.managedPrefixListVersion });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_PROXY_DRIFT_READONLY });
  console.log(JSON.stringify(verifyProductionCloudFrontProxyDrift({ run })));
}
