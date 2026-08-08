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

test("caller-owned pre-existing stdout collision is preserved byte-for-byte", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-json-capture-collision-"));
  fs.chmodSync(directory, 0o700);
  const outputPath = path.join(directory, "stdout.json");
  const sentinel = Buffer.from("caller-owned sentinel\n");
  fs.writeFileSync(outputPath, sentinel, { mode: 0o600, flag: "wx" });
  const before = fs.statSync(outputPath).mode & 0o777;
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stdout.write('{}')"), tempDirectory: directory }), /EEXIST/);
  assert.deepEqual(fs.readFileSync(outputPath), sentinel);
  assert.equal(fs.statSync(outputPath).mode & 0o777, before);
  assert.equal(fs.existsSync(directory), true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("caller-owned invocation-created partial output is removed after subprocess failure", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-json-capture-partial-"));
  fs.chmodSync(directory, 0o700);
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stdout.write('{'); process.exit(3)"), tempDirectory: directory }), /exit 3/);
  assert.equal(fs.existsSync(path.join(directory, "stdout.json")), false);
  assert.equal(fs.existsSync(directory), true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("caller-owned directory survives successful capture", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-json-capture-success-"));
  fs.chmodSync(directory, 0o700);
  const bytes = captureStageBTerraformJson({ ...runNode("process.stdout.write('{}')"), tempDirectory: directory });
  assert.deepEqual(bytes, Buffer.from("{}"));
  assert.deepEqual(fs.readdirSync(directory), []);
  assert.equal(fs.existsSync(directory), true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("helper-owned temporary directory is removed after capture", () => {
  const prefix = "mscqr-stage-b-terraform-show-";
  const before = new Set(fs.readdirSync(os.tmpdir()).filter((entry) => entry.startsWith(prefix)));
  captureStageBTerraformJson({ ...runNode("process.stdout.write('{}')") });
  const after = fs.readdirSync(os.tmpdir()).filter((entry) => entry.startsWith(prefix));
  assert.deepEqual(after.filter((entry) => !before.has(entry)), []);
});

test("caller-owned pre-existing stdout symlink is preserved", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-json-capture-symlink-"));
  fs.chmodSync(directory, 0o700);
  const target = path.join(directory, "sentinel");
  const outputPath = path.join(directory, "stdout.json");
  fs.writeFileSync(target, "symlink target\n", { mode: 0o600, flag: "wx" });
  fs.symlinkSync(target, outputPath);
  assert.throws(() => captureStageBTerraformJson({ ...runNode("process.stdout.write('{}')"), tempDirectory: directory }), /EEXIST/);
  assert.equal(fs.lstatSync(outputPath).isSymbolicLink(), true);
  assert.equal(fs.readFileSync(target, "utf8"), "symlink target\n");
  fs.rmSync(directory, { recursive: true, force: true });
});
