#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { assertProductionDualSlotRebaselineDurableEvidence, productionDualSlotRebaselineDurableEvidenceKey } from "./production-dual-slot-rebaseline-contract.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { assertStageBProtectedMainCheckout, readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const required = (args, name) => { const value = args.get(name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const descendant = ({ ancestorSha, descendantSha }) => { try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; } };
const exactInputKeys = (bundle) => {
  const expected = ["manifest", "preparation", "completion", "bindings", "authorization"];
  if (bundle?.manifest?.mode === "SUCCESSOR_RECOVERY") expected.push("recoveryEnvelope", "imageAuthorization");
  if (!bundle || typeof bundle !== "object" || Object.keys(bundle).some((key) => !expected.includes(key))) throw new Error("Durable rebaseline evidence producer input contains unsupported top-level fields.");
};

export function persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha, run, protectedCheckout = () => readStageBProtectedMainCheckout({ cwd: process.cwd(), fetchOriginMain: true, expectedSourceSha: publisherSourceSha, requireCanonicalRepository: true }), fsOps = { mkdtempSync, readFileSync, rmSync, writeFileSync } } = {}) {
  exactInputKeys(bundle);
  const durablePayload = { manifest: bundle.manifest, preparation: bundle.preparation, completion: bundle.completion, bindings: bundle.bindings };
  assertProductionDualSlotRebaselineDurableEvidence(durablePayload, { publisherSourceSha, authorization: bundle.authorization, recoveryEnvelope: bundle.recoveryEnvelope, imageAuthorization: bundle.imageAuthorization, proveDescendant: descendant });
  const bytes = canonicalBytes(durablePayload);
  const manifest = durablePayload.manifest;
  const key = productionDualSlotRebaselineDurableEvidenceKey({ rotationId: manifest.rotationId, executionSourceSha: manifest.executionSourceSha, authorizationSha256: manifest.authorizationSha256, evidenceSha256: manifest.evidenceSha256 });
  const directory = fsOps.mkdtempSync(path.join(tmpdir(), "mscqr-rebaseline-evidence-")); const body = path.join(directory, "evidence.json"); const readback = path.join(directory, "readback.json");
  try {
    fsOps.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
    const checkout = assertStageBProtectedMainCheckout({ ...protectedCheckout({ expectedSourceSha: publisherSourceSha }), mode: "production" });
    if (checkout.currentHead !== publisherSourceSha || checkout.originMainHead !== publisherSourceSha || checkout.toolingSha !== publisherSourceSha || checkout.porcelainStatus !== "") throw new Error("Durable rebaseline evidence publisher checkout is not the exact clean protected main source.");
    try { run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]); }
    catch (error) { throw new Error(`Durable rebaseline evidence conditional create failed; no overwrite or retry was performed: ${error.message}`); }
    const head = JSON.parse(run(["s3api", "head-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--output", "json", "--no-cli-pager"]));
    if (head.ServerSideEncryption !== "AES256" || head.ContentLength !== bytes.length) throw new Error("Durable rebaseline evidence object encryption or length is not exact.");
    run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--output", "json", "--no-cli-pager", readback]);
    const persisted = fsOps.readFileSync(readback);
    if (!persisted.equals(bytes) || sha256(persisted) !== sha256(bytes)) throw new Error("Durable rebaseline evidence readback differs from the conditionally created canonical bytes.");
    return Object.freeze({ status: "CREATED", bucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket, key, evidenceSha256: manifest.evidenceSha256, objectSha256: sha256(bytes) });
  } finally { fsOps.rmSync(directory, { recursive: true, force: true }); }
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const args = new Map();
  for (let i = 2; i < process.argv.length; i += 2) { const key = process.argv[i]?.replace(/^--/, ""); const value = process.argv[i + 1]; if (!new Set(["input", "source-sha", "profile"]).has(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`); args.set(key, value); }
  const sourceSha = required(args, "source-sha"); const input = Buffer.from(readFileSync(path.resolve(required(args, "input")))); let bundle;
  try { bundle = JSON.parse(input); } catch { throw new Error("Durable rebaseline evidence bundle is malformed."); }
  if (!input.equals(canonicalBytes(bundle))) throw new Error("Durable rebaseline evidence input bytes are not canonical.");
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(args, "profile"), region: "eu-west-2" });
  process.stdout.write(`${JSON.stringify(persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run }), null, 2)}\n`);
}
