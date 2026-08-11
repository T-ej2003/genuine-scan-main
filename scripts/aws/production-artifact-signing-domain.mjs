import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

export const ARTIFACT_SIGNING_BINDINGS = Object.freeze([
  "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT",
  "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT",
  "ARTIFACT_SIGN_ACTIVE_KEY_VERSION",
  "ARTIFACT_SIGN_PUBLIC_KEYS_JSON",
]);
const version = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const pem = (value, name) => {
  const raw = String(value || "").replace(/\\n/g, "\n").trim();
  const decoded = raw.includes("-----BEGIN") ? raw : Buffer.from(raw, "base64").toString("utf8").trim();
  if (!decoded.includes("-----BEGIN")) throw new Error(`${name} is not a PEM value.`);
  return decoded;
};
const fingerprint = (key) => createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");

// Secret values are only held in-process by the approved adapter; the result
// exposes references and public metadata, never material.
export async function verifyArtifactSigningDomain({ bindings, readSecret }) {
  if (!bindings || typeof bindings !== "object" || typeof readSecret !== "function" || !ARTIFACT_SIGNING_BINDINGS.every((name) => typeof bindings[name] === "string" && bindings[name])) throw new Error("Artifact signing bindings are incomplete.");
  const values = Object.fromEntries(await Promise.all(ARTIFACT_SIGNING_BINDINGS.map(async (name) => [name, await readSecret(bindings[name])])));
  const active = String(values.ARTIFACT_SIGN_ACTIVE_KEY_VERSION || "").trim();
  if (!version.test(active)) throw new Error("Artifact signing active key version is invalid.");
  const privateKey = createPrivateKey(pem(values.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT, "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT"));
  const publicKey = createPublicKey(pem(values.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT, "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT"));
  if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") throw new Error("Artifact signing keys must be Ed25519.");
  let registry;
  try { registry = JSON.parse(String(values.ARTIFACT_SIGN_PUBLIC_KEYS_JSON || "")); } catch { throw new Error("Artifact signing public registry is not JSON."); }
  if (!registry || typeof registry !== "object" || Array.isArray(registry) || Object.keys(registry).length === 0 || Object.keys(registry).length > 64) throw new Error("Artifact signing public registry is invalid.");
  if (!Object.hasOwn(registry, active) || /PRIVATE KEY/i.test(String(registry[active] || ""))) throw new Error("Artifact signing active public key is absent from the public registry.");
  const registryKey = createPublicKey(pem(registry[active], "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"));
  if (registryKey.asymmetricKeyType !== "ed25519" || fingerprint(registryKey) !== fingerprint(publicKey)) throw new Error("Artifact signing registry key does not match current public key.");
  const probe = Buffer.from("mscqr-artifact-signing-control-plane", "utf8");
  if (!verify(null, probe, publicKey, sign(null, probe, privateKey))) throw new Error("Artifact signing private/public pair is inconsistent.");
  return { valid: true, activeKeyVersion: active, publicRegistryCount: Object.keys(registry).length, bindings: Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, bindings[name]])) };
}

export async function provisionArtifactSigningDomain({ bindings, approvedBindings, readSecret, putSecret, activeKeyVersion } = {}) {
  if (typeof putSecret !== "function" || !version.test(activeKeyVersion || "")) throw new Error("Artifact signing provisioner inputs are invalid.");
  if (!approvedBindings || !ARTIFACT_SIGNING_BINDINGS.every((name) => bindings?.[name] === approvedBindings[name])) throw new Error("Artifact signing secret target is outside the reviewed allowlist.");
  const values = Object.fromEntries(await Promise.all(ARTIFACT_SIGNING_BINDINGS.map(async (name) => [name, await readSecret(bindings?.[name])])));
  const populated = ARTIFACT_SIGNING_BINDINGS.filter((name) => String(values[name] || "").trim());
  if (populated.length !== 0 && populated.length !== ARTIFACT_SIGNING_BINDINGS.length) throw new Error("Artifact signing domain is partial; refusing repair.");
  if (populated.length === 0) {
    const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
    const writes = {
      ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: pair.privateKey,
      ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: pair.publicKey,
      ARTIFACT_SIGN_ACTIVE_KEY_VERSION: activeKeyVersion,
      ARTIFACT_SIGN_PUBLIC_KEYS_JSON: JSON.stringify({ [activeKeyVersion]: pair.publicKey }),
    };
    for (const name of ARTIFACT_SIGNING_BINDINGS) await putSecret({ secretRef: bindings[name], value: writes[name] });
  }
  return verifyArtifactSigningDomain({ bindings, readSecret });
}
