// This file executes only inside the isolated, network-disabled container.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
async function fileHash(file) {
  const value = createHash("sha256");
  for await (const bytes of fs.createReadStream(file)) value.update(bytes);
  return value.digest("hex");
}
let phase = "input-authentication";
async function main() {
  assert.equal(process.argv.length, 4);
  assert.match(process.argv[2] || "", /^[a-f0-9]{64}$/);
  assert.equal(process.argv[3], "validate", "Unsupported isolated operation");
  const bytes = fs.readFileSync("/inputs/manifest.json");
  assert.equal(hash(bytes), process.argv[2]);
  const manifest = JSON.parse(bytes);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.terraformVersion, "1.15.8"); assert.equal(manifest.providerVersion, "6.65.0");
  const names = ["agent.mjs", "isolation.mjs", "root/main.tf", "root/providers.tf", "root/versions.tf", "root/.terraform.lock.hcl", "terraform", "terraform.rc",
    `providers/registry.terraform.io/hashicorp/aws/terraform-provider-aws_6.65.0_linux_${manifest.architecture}.zip`].sort();
  assert(["amd64", "arm64"].includes(manifest.architecture));
  assert.deepEqual(Object.keys(manifest.files).sort(), names);
  for (const name of names) {
    assert(fs.lstatSync(`/inputs/${name}`).isFile());
    assert.equal(await fileHash(`/inputs/${name}`), manifest.files[name], "Isolated input bytes changed");
  }
  for (const name of ["home", "tmp", "data"]) fs.mkdirSync(`/work/${name}`, { mode: 0o700 });
  const env = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/work/home", TMPDIR: "/work/tmp", LANG: "C", TZ: "UTC",
    CHECKPOINT_DISABLE: "1", TF_IN_AUTOMATION: "true", TF_INPUT: "0", TF_WORKSPACE: "default", TF_DATA_DIR: "/work/data", TF_CLI_CONFIG_FILE: "/inputs/terraform.rc",
    AWS_EC2_METADATA_DISABLED: "true", AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true" };
  const tf = args => new Promise((resolve, reject) => {
    phase = args[0];
    const child = spawn("/inputs/terraform", ["-chdir=/inputs/root", ...args], { env, stdio: ["ignore", "pipe", "ignore"] });
    const chunks = []; let length = 0;
    const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
    child.stdout.on("data", data => { length += data.length; if (length > 16 * 1024 * 1024) child.kill("SIGKILL"); else chunks.push(data); });
    child.on("error", () => { clearTimeout(timer); reject(new Error("Isolated Terraform failed")); });
    child.on("close", code => { clearTimeout(timer); if (code === 0 || args[0] === "validate" && code === 1) resolve(Buffer.concat(chunks).toString()); else reject(new Error("Isolated Terraform rejected")); });
  });
  assert.equal(JSON.parse(await tf(["version", "-json"])).terraform_version, manifest.terraformVersion);
  await tf(["fmt", "-check"]);
  await tf(["init", "-backend=false", "-input=false", "-lockfile=readonly"]);
  const result = JSON.parse(await tf(["validate", "-json"]));
  // This backend-disabled mode receives no credentials and only public reviewed
  // source. Preserve provider validation diagnostics, not opaque SDK exceptions.
  if (!result.valid) process.stderr.write(`${JSON.stringify(result.diagnostics)}\n`);
  assert.equal(result.valid, true);
  assert.equal(hash(fs.readFileSync("/inputs/root/.terraform.lock.hcl")), manifest.files["root/.terraform.lock.hcl"]);
  process.stdout.write(`${JSON.stringify({ type: "result", valid: true, manifestSha256: process.argv[2], terraformVersion: manifest.terraformVersion, providerVersion: manifest.providerVersion })}\n`);
}
main().catch(() => { process.stderr.write(`Isolated Terraform execution rejected at ${phase}.\n`); process.exitCode = 1; });
