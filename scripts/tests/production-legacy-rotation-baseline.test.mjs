import assert from "node:assert/strict";
import test from "node:test";
import { assertBindingsMatchLegacyBaseline, deriveLegacyRotationBaseline } from "../aws/production-legacy-rotation-baseline.mjs";
import { parseEcsSecretsManagerReference } from "../aws/production-ecs-runtime-dependencies.mjs";
import { assertQrVersionSelector, resolveQrVersionSelectorValue } from "../aws/production-qr-version-selector-resolution.mjs";

const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name}`;
const jwt = arn("mscqr/prod/jwt-wBQNqk");
const qrPrivate = arn("mscqr/prod/qr_sign_private_key-AbCd12");
const qrPublic = arn("mscqr/prod/qr_sign_public_key-AbCd12");
const taskDefinition = ({ jwtReference = jwt, privateReference = `${qrPrivate}:value::`, publicReference = `${qrPublic}:value::` } = {}) => ({
  taskDefinition: { containerDefinitions: [{
    name: "backend",
    environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "2026-09-08" }],
    secrets: [
      { name: "JWT_SECRET", valueFrom: jwtReference },
      { name: "QR_SIGN_PRIVATE_KEY", valueFrom: privateReference },
      { name: "QR_SIGN_PUBLIC_KEY", valueFrom: publicReference },
    ],
  }] },
});

test("live-shaped QR value selectors normalize to base rotation resources", () => {
  assert.deepEqual(deriveLegacyRotationBaseline(taskDefinition()), {
    jwtCurrent: jwt,
    qrPrivateCurrent: qrPrivate,
    qrPublicCurrent: qrPublic,
    qrCurrentVersion: "2026-09-08",
  });
});

test("legacy rotation baseline rejects unsafe QR selector shapes and namespace substitution", () => {
  for (const input of [
    { privateReference: qrPrivate },
    { publicReference: qrPublic },
    { privateReference: `${qrPrivate}:wrongKey::` },
    { privateReference: `${qrPrivate}:value:AWSCURRENT:` },
    { privateReference: `${qrPrivate}:value::${"a".repeat(32)}` },
    { privateReference: `${qrPrivate}:value:` },
    { privateReference: `${qrPrivate}:value:::extra` },
    { privateReference: `${arn("mscqr/prod/unrelated-AbCd12")}:value::` },
    { privateReference: `${qrPrivate.replace(":368992683803:", ":000000000000:")}:value::` },
    { privateReference: "arn:aws:ssm:eu-west-2:368992683803:parameter/mscqr/prod/qr_sign_private_key" },
    { privateReference: `${qrPublic}:value::`, publicReference: `${qrPrivate}:value::` },
  ]) assert.throws(() => deriveLegacyRotationBaseline(taskDefinition(input)), /Live legacy qr(?:Private|Public)Current binding is invalid/);
});

test("JWT baseline accepts the live ECS JSON value selector but binds only the underlying secret identity", () => {
  const baseline = deriveLegacyRotationBaseline(taskDefinition({ jwtReference: `${jwt}:value::` }));
  assert.equal(baseline.jwtCurrent, jwt);
  assert.deepEqual(parseEcsSecretsManagerReference(`${jwt}:value::`), { resource: jwt, jsonKey: "value", versionStage: null, versionId: null, selectorMode: "AWSCURRENT" });
  assert.equal(parseEcsSecretsManagerReference(`${jwt}:value:AWSCURRENT:`).selectorMode, "VERSION_STAGE");
  assert.equal(parseEcsSecretsManagerReference(`${jwt}:value::${"a".repeat(32)}`).selectorMode, "VERSION_ID");
  assert.equal(assertBindingsMatchLegacyBaseline({ jwt: { currentSecretId: jwt }, qr: { privateCurrentSecretId: qrPrivate, publicCurrentSecretId: qrPublic, previousKeyVersion: "2026-09-08" } }, baseline), true);
  assert.throws(() => assertBindingsMatchLegacyBaseline({ jwt: { currentSecretId: arn("mscqr/prod/other-AbCd12") }, qr: { privateCurrentSecretId: qrPrivate, publicCurrentSecretId: qrPublic, previousKeyVersion: "2026-09-08" } }, baseline), /do not match/);
  assert.throws(() => parseEcsSecretsManagerReference(`${jwt}:value:AWSCURRENT:${"a".repeat(32)}`), /malformed or ambiguous/);
});

test("JWT baseline rejects selectors that change which stored value rotation authenticates", () => {
  for (const jwtReference of [
    `${jwt}:other::`,
    `${jwt}:value:AWSPREVIOUS:`,
    `${jwt}:value::${"a".repeat(32)}`,
    `${jwt}:value:AWSCURRENT:${"a".repeat(32)}`,
    `${jwt}:value`,
    `${jwt}:value:::extra`,
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:",
    `${jwt.replace(":368992683803:", ":000000000000:")}:value::`,
    `${jwt.replace("secretsmanager", "ssm")}:value::`,
    `${jwt}:value::suffix`,
  ]) assert.throws(() => deriveLegacyRotationBaseline(taskDefinition({ jwtReference })), /Live legacy jwtCurrent binding is invalid/);
});

test("canonical QR version JSON selector derives only its resolved selected identifier", () => {
  const currentVersion = arn("mscqr/prod/rotation/qr-current-version-8fNOVE");
  const live = { taskDefinition: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/backend:19", containerDefinitions: [{ name: "backend", environment: [], secrets: [
    { name: "JWT_SECRET", valueFrom: `${jwt}:value::` }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: `${qrPrivate}:value::` }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: `${qrPublic}:value::` }, { name: "QR_SIGN_ACTIVE_KEY_VERSION", valueFrom: `${currentVersion}:value::` },
  ] }] } };
  assert.throws(() => deriveLegacyRotationBaseline(live), /Live QR active key version is invalid/);
  const binding = assertQrVersionSelector({ taskDefinition: live, expectedSecretArn: currentVersion });
  const resolved = resolveQrVersionSelectorValue({ binding, response: { ARN: currentVersion, VersionId: "a".repeat(32), VersionStages: ["AWSCURRENT"], SecretString: JSON.stringify({ value: "2026-09-08" }) } });
  assert.equal(deriveLegacyRotationBaseline(live, { qrVersionResolution: resolved }).qrCurrentVersion, "2026-09-08");
  assert.throws(() => deriveLegacyRotationBaseline(live, { qrVersionResolution: { ...resolved, secretArn: arn("mscqr/prod/rotation/qr-previous-version-PDFul2") } }), /outside the production contract|exact authorized/);
});
