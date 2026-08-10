import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const script = path.resolve("scripts/aws/verify-version-endpoint.sh");
const expectedGitSha = "5e12983f1fe733473cacb6b213c0c02ef9f38098";

function run(payload, { curlStatus = 0, expected = expectedGitSha } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "verify-version-endpoint-"));
  const bin = path.join(directory, "bin");
  const temp = path.join(directory, "tmp");
  fs.mkdirSync(bin);
  fs.mkdirSync(temp);
  const curl = path.join(bin, "curl");
  fs.writeFileSync(curl, `#!/usr/bin/env bash
set -euo pipefail
if [[ "${curlStatus}" != "0" ]]; then exit "${curlStatus}"; fi
printf '%s\\n' "$FAKE_CURL_PAYLOAD"
`, { mode: 0o755 });
  const result = spawnSync("bash", [script, "https://www.mscqr.com/api/health", expected], {
    cwd: path.resolve("."),
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: temp, FAKE_CURL_PAYLOAD: payload },
  });
  assert.deepEqual(fs.readdirSync(temp), []);
  fs.rmSync(directory, { recursive: true, force: true });
  return result;
}

function assertPass(payload, options) {
  const result = run(payload, options);
  assert.equal(result.status, 0, result.stderr);
}

function assertFail(payload, options) {
  const result = run(payload, options);
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
}

test("top-level gitSha is accepted", () => assertPass(JSON.stringify({ gitSha: expectedGitSha })));
test("health release.gitSha is accepted", () => assertPass(JSON.stringify({ status: "ok", release: { gitSha: expectedGitSha } })));
test("wrong top-level SHA is rejected", () => assertFail(JSON.stringify({ gitSha: "a".repeat(40) })));
test("wrong nested SHA is rejected", () => assertFail(JSON.stringify({ release: { gitSha: "a".repeat(40) } })));
test("missing SHA fields are rejected", () => assertFail(JSON.stringify({ status: "ok", release: { shortGitSha: expectedGitSha.slice(0, 12) } })));
test("matching dual SHA fields are accepted", () => assertPass(JSON.stringify({ gitSha: expectedGitSha, release: { gitSha: expectedGitSha } })));
test("conflicting dual SHA fields are rejected", () => assertFail(JSON.stringify({ gitSha: expectedGitSha, release: { gitSha: "a".repeat(40) } })));
test("shortGitSha alone is rejected", () => assertFail(JSON.stringify({ shortGitSha: expectedGitSha.slice(0, 12) })));
test("malformed SHA is rejected", () => assertFail(JSON.stringify({ release: { gitSha: "not-a-sha" } })));
test("uppercase SHA is rejected", () => assertFail(JSON.stringify({ release: { gitSha: expectedGitSha.toUpperCase() } })));
test("invalid JSON is rejected", () => assertFail("not-json"));
test("HTTP failure is rejected", () => assertFail("", { curlStatus: 22 }));
test("uppercase expected SHA is rejected before HTTP", () => assertFail(JSON.stringify({ gitSha: expectedGitSha }), { expected: expectedGitSha.toUpperCase() }));
