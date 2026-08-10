import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(path, "utf8");
const template = read("infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-rotation-candidate.json");
const terraform = read("infra/aws/terraform/production-green-stage-b/main.tf");
const variables = read("infra/aws/terraform/production-green-stage-b/variables.tf");
const qr = read("backend/src/services/qrTokenService.ts");
const jwt = read("backend/src/utils/secretConfig.ts");
const coordinator = read("backend/scripts/security/rotate-production-signing-material.mjs");

test("rotation task template is dual-slot and Ed25519-only", () => {
  for (const placeholder of [
    "{{JWT_SECRET_CURRENT}}",
    "{{JWT_SECRET_PREVIOUS}}",
    "{{QR_SIGN_PRIVATE_KEY_CURRENT}}",
    "{{QR_SIGN_PUBLIC_KEY_CURRENT}}",
    "{{QR_SIGN_ACTIVE_KEY_VERSION}}",
    "{{QR_SIGN_PUBLIC_KEY_PREVIOUS}}",
    "{{QR_SIGN_PREVIOUS_KEY_VERSION}}",
  ]) assert.match(template, new RegExp(placeholder.replace(/[{}]/g, "\\$&")));
  assert.doesNotMatch(template, /QR_SIGN_HMAC/);
  assert.match(template, /"containerPort": 4000/);
  assert.match(template, /"protocol": "tcp"/);
});

test("runtime contracts issue current and verify only current plus one previous slot", () => {
  assert.match(jwt, /currentKeys: \["JWT_SECRET_CURRENT"\]/);
  assert.match(jwt, /previousKeys: \["JWT_SECRET_PREVIOUS"\]/);
  assert.match(qr, /readPreviousPublicKey/);
  assert.match(qr, /keys\.push\(\{ version: previousVersion/);
  assert.match(qr, /if \(!matchedKey\) throw new QrTokenVerificationError/);
  assert.match(qr, /requestedKeyVersion !== signingProfile\.keyVersion/);
  assert.match(qr, /QR_SIGN_PRIVATE_KEY_PREVIOUS/);
});

test("Terraform rotation mode is opt-in and references exact Secrets Manager JSON keys", () => {
  assert.match(terraform, /production_rotation_enabled/);
  assert.match(terraform, /production_rotation_secret_value_from/);
  assert.match(variables, /Production rotation task definitions require exact Secrets Manager JSON-key valueFrom references/);
  assert.match(variables, /current and previous secret references\/version references must be distinct/);
});

test("coordinator exposes explicit resumable phases and no implicit cleanup", () => {
  for (const mode of ["--prepare", "--verify", "--cleanup", "--status"]) assert.match(coordinator, new RegExp(mode.slice(2)));
  assert.match(coordinator, /exactly one of --prepare, --verify, --cleanup, or --status/);
  assert.match(coordinator, /--confirm-cleanup is required for cleanup/);
  assert.match(coordinator, /config\.qr\.previousKeyVersion/);
  assert.match(coordinator, /deploymentRequired: true/);
  assert.doesNotMatch(coordinator, /console\.log\([^\n]*SecretString/);
});
