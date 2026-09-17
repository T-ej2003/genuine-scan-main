import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { prepareIsolatedTerraformInputs } from "./component-terraform-inputs.mjs";
import { createTerraformRelay, terraformDockerArguments } from "./component-terraform-isolation.mjs";

// Private composition API, not a command dispatcher. Only fixed source inputs
// are prepared; checkpoint authorization belongs to the activation controller.
export async function executeIsolatedTerraform(request, { checkpoint, prepare = prepareIsolatedTerraformInputs } = {}) {
  assert.deepEqual(Object.keys(request).sort(), ["credentials", "expiresAt", "mode", "plan"]);
  assert(["prepare", "apply"].includes(request.mode));
  assert.equal(typeof checkpoint, "function");
  assert.deepEqual(Object.keys(request.credentials).sort(), ["AccessKeyId", "SecretAccessKey", "SessionToken"]);
  for (const value of Object.values(request.credentials)) assert(typeof value === "string" && value.length > 0 && value.length < 16384);
  const expires = Date.parse(request.expiresAt);
  assert(Number.isFinite(expires) && expires > Date.now() + 120000 && expires <= Date.now() + 901000);
  if (request.mode === "prepare") assert.equal(request.plan, null);
  else assert(Buffer.isBuffer(request.plan) && request.plan.length > 0 && request.plan.length <= 16 * 1024 * 1024);
  const binary = process.platform === "darwin" ? "/usr/local/bin/docker" : "/usr/bin/docker";
  assert(fs.statSync(binary).isFile());
  const socket = process.platform === "darwin" ? path.join(os.homedir(), ".docker/run/docker.sock") : "/var/run/docker.sock";
  assert(fs.statSync(socket).isSocket(), "A local Docker daemon is required");
  const inputs = await prepare();
  const client = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-docker-client-"));
  fs.chmodSync(client, 0o700);
  const name = `mscqr-component-terraform-${randomUUID()}`;
  const prefix = ["--config", client, "--host", `unix://${socket}`];
  // No AWS or GitHub credential environment is passed to the Docker client.
  const environment = { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: client, LANG: "C" };
  let child;
  try {
    return await new Promise((resolve, reject) => {
      let buffer = "", result, ready = false, stage = "ready", failed = false;
      const stop = () => { if (failed) return; failed = true; relay.close(); child.stdin.destroy(); child.kill("SIGTERM"); };
      const send = message => {
        assert(!failed && child.stdin.writable && child.stdin.writableLength < 32 * 1024 * 1024);
        child.stdin.write(`${JSON.stringify(message)}\n`);
      };
      const relay = createTerraformRelay({ send, fail: stop });
      const args = terraformDockerArguments(inputs.directory);
      args.splice(1, 0, `--name=${name}`);
      child = spawn(binary, [...prefix, ...args, inputs.manifestSha256, request.mode], { env: environment, stdio: ["pipe", "pipe", "ignore"] });
      const timer = setTimeout(stop, Math.max(1, expires - Date.now() - 10000));
      child.stdin.on("error", stop);
      let chain = Promise.resolve();
      const message = async value => {
        assert(!failed);
        if (["open", "data", "close"].includes(value.type)) return relay.receive(value);
        if (value.type === "ready") {
          assert(!ready && stage === "ready");
          assert.deepEqual(value, { type: "ready", manifestSha256: inputs.manifestSha256 }); ready = true; stage = "backend";
          send({ type: "execution", manifestSha256: inputs.manifestSha256, credentials: request.credentials, expiresAt: request.expiresAt, plan: request.plan?.toString("base64") ?? null });
        } else if (value.type === "checkpoint") {
          assert(ready && value.stage === stage);
          assert.deepEqual(Object.keys(value).sort(), stage === "backend" ? ["backend", "stage", "type", "workspace"] : ["planJson", "planSha256", "stage", "type"]);
          await checkpoint(value);
          assert(Date.now() < expires - 10000);
          send({ type: "continue", stage, manifestSha256: inputs.manifestSha256 });
          stage = stage === "backend" ? request.mode === "apply" ? "apply" : "plan" : "result";
        } else {
          assert(ready && stage === "result" && value.type === "result" && !result);
          assert.deepEqual(Object.keys(value).sort(), request.mode === "prepare" ? ["plan", "planJson", "planSha256", "type"] : ["appliedPlanSha256", "driftVerified", "type"]);
          result = value; stage = "closed";
        }
      };
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", data => {
        try {
          buffer += data; assert(buffer.length <= 32 * 1024 * 1024);
          let boundary;
          while ((boundary = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 1);
            const value = JSON.parse(line);
            // Relay traffic cannot wait behind an approval callback; that could
            // deadlock a TLS read while the host authenticates a checkpoint.
            if (["open", "data", "close"].includes(value.type)) void relay.receive(value);
            else chain = chain.then(() => message(value)).catch(stop);
          }
        } catch { stop(); }
      });
      child.on("error", stop);
      child.on("close", async code => {
        clearTimeout(timer); relay.close(); await chain;
        if (!failed && code === 0 && !buffer && result) resolve(result);
        else reject(new Error("Isolated Terraform failed; reconcile remote state before retry"));
      });
    });
  } finally {
    // Exact newly owned container only. This also covers attach-client loss;
    // --rm alone is not a guarantee that the container stopped with its client.
    const control = args => new Promise(resolve => {
      const command = spawn(binary, [...prefix, ...args], { env: environment, stdio: ["ignore", "ignore", "pipe"] });
      let error = "";
      command.stderr.on("data", bytes => { if (error.length < 4096) error += bytes.toString(); });
      const timer = setTimeout(() => command.kill("SIGKILL"), 10000);
      command.on("error", () => { clearTimeout(timer); resolve({ code: null, error: "" }); });
      command.on("close", code => { clearTimeout(timer); resolve({ code, error }); });
    });
    try {
      await control(["rm", "--force", name]);
      const observed = await control(["container", "inspect", name]);
      assert(observed.code === 1 && /No such (?:object|container):/.test(observed.error), "Owned executor absence is unproven; reconcile its exact container before retry");
    } finally { inputs.dispose(); fs.rmSync(client, { recursive: true }); }
  }
}
