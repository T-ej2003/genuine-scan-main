import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

const { validateQrSigningConfiguration } = await import("../../backend/dist/services/qrTokenService.js");

test("Node 24 accepts extracted Ed25519 PEM and rejects the JSON secret envelope", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  process.env.QR_SIGN_ACTIVE_KEY_VERSION = "test-v1";
  process.env.QR_SIGN_PRIVATE_KEY = privatePem;
  process.env.QR_SIGN_PUBLIC_KEY = publicPem;
  assert.equal(validateQrSigningConfiguration().mode, "ed25519");

  process.env.QR_SIGN_PRIVATE_KEY = JSON.stringify({ value: privatePem });
  process.env.QR_SIGN_PUBLIC_KEY = JSON.stringify({ value: publicPem });
  assert.throws(
    () => validateQrSigningConfiguration(),
    (error) => error?.code === "QR_SIGNING_CONFIGURATION_INVALID",
  );
});
