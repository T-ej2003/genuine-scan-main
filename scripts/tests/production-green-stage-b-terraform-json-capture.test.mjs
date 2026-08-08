import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { captureStageBTerraformJson } from "../aws/capture-stage-b-terraform-json.mjs";

const cwd = process.cwd();
const runNode = (script, value) => ({ terraform: process.execPath, args: ["-e", script, ...(value === undefined ? [] : [value])], cwd });

test("large terraform show JSON is captured without child-process stdout buffering", () => {
  const payload = JSON.stringify({ format_version: "1.2", payload: "x".repeat(2 * 1024 * 1024) });
  const bytes = captureStageBTerraformJson({ ...runNode("process.stdout.write(JSON.stringify({ format_version: '1.2', payload: 'x'.repeat(Number(process.argv[1])) }))", String(2 * 1024 * 1024)) });
  assert.equal(bytes.toString("utf8"), payload);
  assert.ok(bytes.length > 1024 * 1024);
});

test("malformed JSON, nonzero exit, spawn failure, and signals fail closed", () => {
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stdout.write('{')") }), /malformed plan JSON/);
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stderr.write('failed'); process.exit(3)") }), /exit 3/);
  assert.throws(() => captureStageBTerraformJson({ terraform: path.join(os.tmpdir(), "missing-stage-b-terraform"), args: [], cwd }), /failed to start/);
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.kill(process.pid, 'SIGTERM')") }), /SIGTERM/);
});

test("capture leaves no partial output and uses a private temporary directory", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-json-capture-test-"));
  fs.chmodSync(directory, 0o700);
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stdout.write('{')"), tempDirectory: directory }), /malformed plan JSON/);
  assert.deepEqual(fs.readdirSync(directory), []);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  fs.rmSync(directory, { recursive: true, force: true });
});
