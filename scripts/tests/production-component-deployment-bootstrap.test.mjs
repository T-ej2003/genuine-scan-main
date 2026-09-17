import assert from "node:assert/strict";
import test from "node:test";
import { bootstrapProductionComponentStateFromLive } from "../aws/bootstrap-production-component-deployment-state.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { WEB_RELEASE } from "../aws/production-web-release-contract.mjs";

const backendSha = "a".repeat(40), frontendSha = "b".repeat(40);
const digest = (letter) => `sha256:${letter.repeat(64)}`;
const backendArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:7`;
const frontendArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${WEB_RELEASE.family}:21`;
const service = (name, arn) => ({ clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", serviceName: name, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, taskDefinition: arn, deployments: [{ status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: arn }] });

function runner({ caller = "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-state-bootstrap/test", backendSource = backendSha } = {}) {
  return (args) => {
    const [serviceName] = args.includes("--services") ? args.slice(args.indexOf("--services") + 1) : [];
    if (args[0] === "sts") return JSON.stringify({ Account: "368992683803", Arn: caller });
    if (args[0] === "ecs" && args[1] === "describe-services") return JSON.stringify({ failures: [], services: [service(serviceName, serviceName === APP_ONLY.service ? backendArn : frontendArn)] });
    if (args[0] === "ecs" && args[1] === "describe-task-definition") {
      const arn = args[args.indexOf("--task-definition") + 1];
      return JSON.stringify({ taskDefinition: arn === backendArn ? { taskDefinitionArn: arn, family: APP_ONLY.family, status: "ACTIVE", containerDefinitions: [{ name: APP_ONLY.container, image: `${APP_ONLY.backendRepository}@${digest("1")}` }] } : { taskDefinitionArn: arn, family: WEB_RELEASE.family, status: "ACTIVE", containerDefinitions: [{ name: WEB_RELEASE.container, image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}@${digest("2")}` }] } });
    }
    if (args[0] === "ecr") { const imageDigest = args.find((value) => value.startsWith("imageDigest=")).slice("imageDigest=".length); return JSON.stringify({ imageDetails: [{ repositoryName: imageDigest === digest("1") ? "mscqr-backend" : "mscqr-web", registryId: "368992683803", imageDigest, imageTags: [imageDigest === digest("1") ? backendSource : frontendSha] }] }); }
    throw new Error(`unexpected ${args.join(" ")}`);
  };
}

test("bootstrap derives each live service identity and leaves unproven database/security null", () => {
  const state = bootstrapProductionComponentStateFromLive({ run: runner(), isProtectedMainAncestor: (value) => [backendSha, frontendSha].includes(value), now: "2026-01-01T00:00:00.000Z" });
  assert.equal(state.components.backend.sourceSha, backendSha); assert.equal(state.components.frontend.sourceSha, frontendSha);
  assert.equal(state.components.database, null); assert.equal(state.components.security, null);
});

test("bootstrap rejects caller substitution and non-main image identities", () => {
  assert.throws(() => bootstrapProductionComponentStateFromLive({ run: runner({ caller: "arn:aws:sts::368992683803:assumed-role/other/test" }), isProtectedMainAncestor: () => true }), /component-state-bootstrap/);
  assert.throws(() => bootstrapProductionComponentStateFromLive({ run: runner({ backendSource: "c".repeat(40) }), isProtectedMainAncestor: () => false }), /protected-main/);
});
