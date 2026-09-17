// This file executes only inside the isolated, network-disabled container.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createIsolatedTerraformProxy } from "./component-terraform-network.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
async function fileHash(file) {
  const value = createHash("sha256");
  for await (const bytes of fs.createReadStream(file)) value.update(bytes);
  return value.digest("hex");
}
let phase = "input-authentication";
let activeChild, transport;
const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);
async function main() {
  assert.equal(process.argv.length, 4);
  assert.match(process.argv[2] || "", /^[a-f0-9]{64}$/);
  const mode = process.argv[3];
  assert(["validate", "prepare", "apply"].includes(mode), "Unsupported isolated operation");
  const bytes = fs.readFileSync("/inputs/manifest.json");
  assert.equal(hash(bytes), process.argv[2]);
  const manifest = JSON.parse(bytes);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.terraformVersion, "1.15.8"); assert.equal(manifest.providerVersion, "6.65.0");
  const names = ["agent.mjs", "component-terraform-isolation.mjs", "component-terraform-network.mjs", "root/main.tf", "root/providers.tf", "root/versions.tf", "root/.terraform.lock.hcl", "terraform", "terraform.rc",
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
  let expiresAt = Infinity, input, lines, waiter;
  if (mode !== "validate") {
    const reject = () => { activeChild?.kill("SIGKILL"); process.exitCode = 1; transport?.close(); lines?.close(); process.stdin.destroy(); waiter?.reject(new Error("Isolated transport failed")); };
    transport = await createIsolatedTerraformProxy({ send: emit, fail: reject });
    const wait = () => new Promise((resolve, rejectWait) => { assert(!waiter); waiter = { resolve, reject: rejectWait }; });
    const first = wait();
    lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    lines.on("line", line => {
      try {
        assert(line.length <= 24 * 1024 * 1024);
        const message = JSON.parse(line);
        if (["connected", "data", "closed"].includes(message.type)) transport.receive(message);
        else { assert(waiter); const pending = waiter; waiter = undefined; pending.resolve(message); }
      } catch { reject(); }
    });
    lines.on("close", () => { if (waiter) reject(); });
    emit({ type: "ready", manifestSha256: process.argv[2] });
    input = await first;
    assert.deepEqual(Object.keys(input).sort(), ["credentials", "expiresAt", "manifestSha256", "plan", "type"]);
    assert.equal(input.type, "execution"); assert.equal(input.manifestSha256, process.argv[2]);
    expiresAt = Date.parse(input.expiresAt);
    assert(Number.isFinite(expiresAt) && expiresAt > Date.now() + 120000 && expiresAt <= Date.now() + 901000);
    assert.deepEqual(Object.keys(input.credentials).sort(), ["AccessKeyId", "SecretAccessKey", "SessionToken"]);
    for (const key of Object.keys(input.credentials)) assert(typeof input.credentials[key] === "string" && input.credentials[key].length > 0 && input.credentials[key].length < 16384);
    Object.assign(env, { AWS_ACCESS_KEY_ID: input.credentials.AccessKeyId, AWS_SECRET_ACCESS_KEY: input.credentials.SecretAccessKey, AWS_SESSION_TOKEN: input.credentials.SessionToken,
      HTTPS_PROXY: transport.url, HTTP_PROXY: transport.url, NO_PROXY: "", AWS_MAX_ATTEMPTS: "1" });
    delete input.credentials;
    input.barrier = async checkpoint => {
      const continuation = wait(); emit({ type: "checkpoint", ...checkpoint });
      const response = await continuation;
      assert.deepEqual(response, { type: "continue", stage: checkpoint.stage, manifestSha256: process.argv[2] });
      assert(Date.now() < expiresAt - 10000, "Execution session expired");
    };
  }
  const tf = args => new Promise((resolve, reject) => {
    phase = args[0];
    assert(Date.now() < expiresAt - 10000, "Execution session expired");
    const child = spawn("/inputs/terraform", ["-chdir=/inputs/root", ...args], { env, stdio: ["ignore", "pipe", "ignore"] });
    activeChild = child;
    const chunks = []; let length = 0;
    const timer = setTimeout(() => child.kill("SIGKILL"), Math.min(120000, expiresAt - Date.now() - 10000));
    child.stdout.on("data", data => { length += data.length; if (length > 16 * 1024 * 1024) child.kill("SIGKILL"); else chunks.push(data); });
    child.on("error", () => { clearTimeout(timer); reject(new Error("Isolated Terraform failed")); });
    child.on("close", code => { clearTimeout(timer); if (code === 0 || args[0] === "validate" && code === 1) resolve(Buffer.concat(chunks).toString()); else reject(new Error("Isolated Terraform rejected")); });
  });
  assert.equal(JSON.parse(await tf(["version", "-json"])).terraform_version, manifest.terraformVersion);
  await tf(["fmt", "-check"]);
  await tf(["init", ...(mode === "validate" ? ["-backend=false"] : []), "-input=false", "-lockfile=readonly"]);
  const result = JSON.parse(await tf(["validate", "-json"]));
  // This backend-disabled mode receives no credentials and only public reviewed
  // source. Preserve provider validation diagnostics, not opaque SDK exceptions.
  if (!result.valid && mode === "validate") process.stderr.write(`${JSON.stringify(result.diagnostics)}\n`);
  assert.equal(result.valid, true);
  assert.equal(hash(fs.readFileSync("/inputs/root/.terraform.lock.hcl")), manifest.files["root/.terraform.lock.hcl"]);
  if (mode === "validate") emit({ type: "result", valid: true, manifestSha256: process.argv[2], terraformVersion: manifest.terraformVersion, providerVersion: manifest.providerVersion });
  else {
    const backend = JSON.parse(fs.readFileSync("/work/data/terraform.tfstate")).backend;
    const workspace = (await tf(["workspace", "show"])).trim();
    await input.barrier({ stage: "backend", backend, workspace });
    const planPath = "/work/activation.tfplan";
    if (mode === "prepare") {
      assert.equal(input.plan, null);
      await tf(["plan", "-input=false", "-lock-timeout=0s", `-out=${planPath}`]);
    } else {
      assert(typeof input.plan === "string" && input.plan.length < 24 * 1024 * 1024);
      const plan = Buffer.from(input.plan, "base64"); assert.equal(plan.toString("base64"), input.plan);
      fs.writeFileSync(planPath, plan, { mode: 0o600, flag: "wx" });
    }
    const planSha256 = await fileHash(planPath);
    const planJson = JSON.parse(await tf(["show", "-json", planPath]));
    if (mode === "prepare") emit({ type: "result", plan: fs.readFileSync(planPath).toString("base64"), planSha256, planJson });
    else {
      await input.barrier({ stage: "apply", planSha256, planJson });
      assert.equal(await fileHash(planPath), planSha256);
      await tf(["apply", "-input=false", "-lock-timeout=0s", planPath]);
      await tf(["plan", "-input=false", "-lock-timeout=0s", "-detailed-exitcode"]);
      emit({ type: "result", appliedPlanSha256: planSha256, driftVerified: true });
    }
    transport.close(); lines.close(); process.stdin.destroy();
  }
}
main().catch(() => { activeChild?.kill("SIGKILL"); transport?.close(); process.stdin.destroy(); process.stderr.write(`Isolated Terraform execution rejected at ${phase}.\n`); process.exitCode = 1; });
