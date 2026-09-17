import assert from "node:assert/strict";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { commitSecurityComponentState } from "../aws/commit-production-component-security-state.mjs";

const source = "b".repeat(40);
const state = () => createProductionComponentDeploymentState({ components: {
  backend: { sourceSha: "a".repeat(40), imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend:1", desiredCount: 2 },
  frontend: { sourceSha: "a".repeat(40), imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:1", desiredCount: 2 }, database: null, security: null,
} });

test("security terminal advances only the authenticated security component", () => {
  const body = { sourceSha: source, valid: true }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const initial = state(); let request;
  const result = commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: (_current, next) => { request = next; } }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha); assert.equal(request.components.frontend.sourceSha, initial.components.frontend.sourceSha);
});

test("security terminal rejects forged authorization and non-main source", () => {
  const initial = state();
  assert.throws(() => commitSecurityComponentState({ sourceSha: source, authorization: { sourceSha: source, authorizationSha256: "0".repeat(64) }, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }), /integrity/);
  const body = { sourceSha: source, valid: true }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  assert.throws(() => commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => false }), /protected-main/);
});

test("a verified security rotation may refresh only its release identity at the same source", () => {
  const initial = createProductionComponentDeploymentState({ components: { ...state().components, security: { sourceSha: source, releaseIdentity: "a".repeat(64) } } });
  const body = { sourceSha: source, valid: true, rotation: "overlap" }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.security.releaseIdentity, authorization.authorizationSha256);
  assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha);
});
