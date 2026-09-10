#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { assertMixedDualSlotRecoveryPreparation } from "./production-mixed-dual-slot-recovery-contract.mjs";
import { assertMixedDualSlotRecoveryIamAttestation } from "./production-mixed-dual-slot-recovery-iam-attestation.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (name) => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
const required = (name) => { const value = option(name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const read = (file, label) => { const captured = readStageBPrivateFileBytes({ filePath: path.resolve(file), repositoryRoot: root, label }); return { ...captured, value: JSON.parse(captured.bytes.toString("utf8")) }; };

const sourceSha = required("--source-sha");
const preparation = read(required("--preparation"), "Mixed recovery preparation");
if (preparation.sha256 !== required("--preparation-file-sha256")) throw new Error("Mixed recovery preparation bytes changed after review.");
assertMixedDualSlotRecoveryPreparation(preparation.value, { sourceSha });
const attestation = read(required("--iam-preflight-attestation"), "Mixed recovery IAM attestation");
if (attestation.sha256 !== required("--iam-preflight-attestation-file-sha256")) throw new Error("Mixed recovery IAM attestation bytes changed after review.");
assertMixedDualSlotRecoveryIamAttestation(attestation.value, { preflight: preparation.value.iamCapabilityPreflight, sourceSha, verify: createPinnedRootAttestationVerifier() });
process.stdout.write(`${JSON.stringify({ status: "IAM_CAPABILITY_ATTESTATION_AUTHENTICATED", attestationSha256: attestation.value.attestationSha256 })}\n`);
