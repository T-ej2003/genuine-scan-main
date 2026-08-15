import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";

const helper = path.resolve("scripts/aws/cosign-idempotent-sign-and-attest.sh");
const digest = `sha256:${"a".repeat(64)}`;
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const identity = "^https://github.com/T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@.*$";
const issuer = "https://token.actions.githubusercontent.com";
const spdxType = "https://spdx.dev/Document";
const provenanceType = "https://mscqr.com/attestations/stage-b-provenance/v1";
const spdxPredicate = { spdxVersion: "SPDX-2.3", name: "mscqr-backend" };
const provenancePredicate = { sourceSha: "3d5eeefc34d69820e00bef072da3c4396689491f", workflowRunId: "31876252809" };

function verifiedEnvelope(predicate, predicateType, subjectDigest = "a".repeat(64)) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: image.split("@")[0], digest: { sha256: subjectDigest } }],
    predicateType,
    predicate,
  };
  return JSON.stringify({
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
    signatures: [{ sig: "cryptographically-verified-by-cosign" }],
  });
}

function verifiedOutput(predicates, predicateType = spdxType) {
  return predicates.map(({ predicate, subjectDigest }) => verifiedEnvelope(predicate, predicateType, subjectDigest)).join("\n");
}

function fixture(mode) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cosign-idempotency-"));
  const log = path.join(directory, "cosign.log");
  const fakeCosign = path.join(directory, "cosign");
  fs.writeFileSync(fakeCosign, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_COSIGN_LOG"
command="$1"
if [[ "$command" == "sign" || "$command" == "attest" ]]; then
  case "$FAKE_COSIGN_MODE" in
    success) exit 0 ;;
    equivalent|wrong-digest|wrong-signature|wrong-certificate|wrong-oidc) echo 'createLogEntryConflict an equivalent entry already exists in the transparency log' >&2; exit 1 ;;
    unrelated) echo 'createLogEntryConflict an unrelated entry exists in the transparency log' >&2; exit 1 ;;
    malformed) echo 'createLogEntryConflict' >&2; exit 1 ;;
    unavailable) echo 'connection refused' >&2; exit 1 ;;
    generic) echo 'signing failed' >&2; exit 1 ;;
  esac
fi
if [[ "$command" == "verify-attestation" ]]; then
  case "$FAKE_COSIGN_MODE" in
    verification-failure|wrong-oidc|wrong-certificate|wrong-tlog) exit 1 ;;
    *) printf '%s' "$FAKE_COSIGN_OUTPUT"; exit 0 ;;
  esac
fi
if [[ "$FAKE_COSIGN_MODE" == "verified" || "$FAKE_COSIGN_MODE" == "equivalent" ]]; then exit 0; fi
exit 1
`, { mode: 0o700 });
  return { directory, log, fakeCosign };
}

function run(mode, operation = ["sign", image], output = "") {
  const { directory, log } = fixture(mode);
  try {
    const env = { ...process.env, PATH: `${directory}:${process.env.PATH}`, FAKE_COSIGN_LOG: log, FAKE_COSIGN_MODE: mode, FAKE_COSIGN_OUTPUT: output, COSIGN_CERT_IDENTITY_REGEXP: identity, COSIGN_CERT_OIDC_ISSUER: issuer };
    const result = (() => {
      try {
        execFileSync(helper, operation, { env, encoding: "utf8", stdio: "pipe" });
        return { status: 0 };
      } catch (error) {
        return { status: error.status, stderr: String(error.stderr || "") };
      }
    })();
    return { ...result, calls: fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : [] };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function runAttestation(mode, predicate, predicateType = "spdxjson", output = verifiedOutput([{ predicate }], predicateType === "spdxjson" ? spdxType : predicateType)) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cosign-predicate-"));
  const predicatePath = path.join(directory, "predicate.json");
  fs.writeFileSync(predicatePath, JSON.stringify(predicate));
  try {
    return run(mode, ["attest", image, predicateType, predicatePath], output);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("fresh signing succeeds without invoking recovery verification", () => {
  const result = run("success");
  assert.equal(result.status, 0);
  assert.deepEqual(result.calls, [`sign --yes ${image}`]);
});

test("exact equivalent Rekor conflict is accepted only after constrained verification", () => {
  const result = run("equivalent");
  assert.equal(result.status, 0);
  assert.equal(result.calls.length, 2);
  assert.ok(result.calls[1].includes(`verify --certificate-identity-regexp ${identity}`));
  assert.ok(result.calls[1].includes(`--certificate-oidc-issuer ${issuer}`));
  assert.ok(result.calls[1].includes(image));
});

test("recovered attestations use the exact predicate type and image digest", () => {
  const result = runAttestation("equivalent", spdxPredicate);
  assert.equal(result.status, 0);
  assert.ok(result.calls[0].includes("attest --yes --type spdxjson --predicate"));
  assert.ok(result.calls[1].includes("verify-attestation --output text --type spdxjson"));
  assert.ok(result.calls[1].includes(image));
});

test("exact recovered SPDX predicate passes and insignificant JSON formatting/order is canonicalized", () => {
  const result = runAttestation("equivalent", { name: "mscqr-backend", spdxVersion: "SPDX-2.3" }, "spdxjson", verifiedOutput([{ predicate: spdxPredicate }]));
  assert.equal(result.status, 0);
});

test("stale, extra, missing, wrong-type, wrong-digest, malformed, and unsigned predicate payloads fail closed", () => {
  const cases = [
    ["stale same-type", verifiedOutput([{ predicate: { ...spdxPredicate, name: "old" } }])],
    ["extra field", verifiedOutput([{ predicate: { ...spdxPredicate, extra: true } }])],
    ["missing field", verifiedOutput([{ predicate: { name: spdxPredicate.name } }])],
    ["wrong predicate type", verifiedOutput([{ predicate: spdxPredicate }], "https://wrong.example/predicate")],
    ["wrong image digest", verifiedOutput([{ predicate: spdxPredicate, subjectDigest: "b".repeat(64) }])],
    ["malformed output", "not-json"],
    ["malformed DSSE payload", JSON.stringify({ payloadType: "application/vnd.in-toto+json", payload: Buffer.from("not-json").toString("base64"), signatures: [{ sig: "verified" }] })],
  ];
  for (const [label, output] of cases) assert.notEqual(runAttestation("equivalent", spdxPredicate, "spdxjson", output).status, 0, label);
});

test("exact recovered provenance predicate passes while changed source or workflow identity fails", () => {
  assert.equal(runAttestation("equivalent", provenancePredicate, provenanceType, verifiedOutput([{ predicate: provenancePredicate }], provenanceType)).status, 0);
  assert.notEqual(runAttestation("equivalent", provenancePredicate, provenanceType, verifiedOutput([{ predicate: { ...provenancePredicate, sourceSha: "4".repeat(40) } }], provenanceType)).status, 0);
  assert.notEqual(runAttestation("equivalent", provenancePredicate, provenanceType, verifiedOutput([{ predicate: { ...provenancePredicate, workflowRunId: "different" } }], provenanceType)).status, 0);
});

test("multiple verified same-type attestations require one exact predicate match", () => {
  const exact = verifiedOutput([{ predicate: spdxPredicate }]);
  const stale = verifiedOutput([{ predicate: { ...spdxPredicate, name: "old" } }]);
  assert.equal(runAttestation("equivalent", spdxPredicate, "spdxjson", `${stale}\n${exact}`).status, 0);
  assert.notEqual(runAttestation("equivalent", spdxPredicate, "spdxjson", stale).status, 0);
});

test("verified OIDC or transparency-log failure is never converted into predicate recovery", () => {
  for (const mode of ["wrong-oidc", "wrong-certificate", "wrong-tlog", "verification-failure"]) {
    assert.notEqual(runAttestation(mode, spdxPredicate).status, 0, mode);
  }
});

test("different digest, signature, certificate, OIDC, malformed response, unavailable Rekor, and generic failures fail closed", () => {
  for (const mode of ["wrong-digest", "wrong-signature", "wrong-certificate", "wrong-oidc"]) {
    const result = run(mode);
    assert.notEqual(result.status, 0, mode);
  }
  for (const mode of ["unrelated", "malformed", "unavailable", "generic"]) {
    const result = run(mode);
    assert.notEqual(result.status, 0, mode);
  }
});

test("helper rejects non-immutable image references and unsupported attestation types", () => {
  const invalidImage = run("success", ["sign", image.replace(/@.*/, ":latest")]);
  assert.equal(invalidImage.status, 2);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cosign-type-"));
  const predicate = path.join(directory, "predicate.json");
  fs.writeFileSync(predicate, "{}");
  try {
    const invalidType = run("success", ["attest", image, "wrong-type", predicate]);
    assert.equal(invalidType.status, 2);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
