import assert from "node:assert/strict";
import test from "node:test";
import { deriveLegacyRotationBaseline } from "../aws/production-legacy-rotation-baseline.mjs";

const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name}`;
const jwt = arn("mscqr/prod/jwt_secret-AbCd12");
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

test("JWT baseline remains bare and selector-free", () => {
  assert.equal(deriveLegacyRotationBaseline(taskDefinition()).jwtCurrent, jwt);
  assert.throws(() => deriveLegacyRotationBaseline(taskDefinition({ jwtReference: `${jwt}:value::` })), /Live legacy jwtCurrent binding is invalid/);
});
