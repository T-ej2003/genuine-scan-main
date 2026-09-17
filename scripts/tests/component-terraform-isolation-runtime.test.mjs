import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { terraformDockerArguments } from "../aws/component-terraform-isolation.mjs";
import { prepareIsolatedTerraformInputs } from "../aws/component-terraform-inputs.mjs";

// Explicit local/CI runtime gate. No AWS credentials, Terraform production call,
// image build/publication, existing container or Docker volume is touched.
test("real isolated container cannot access host credentials, control sockets, writable inputs or metadata", { skip: process.env.COMPONENT_CONTAINER_TESTS !== "1" }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-terraform-inputs-"));
  fs.chmodSync(directory, 0o700);
  try {
    fs.writeFileSync(path.join(directory, "marker"), "reviewed-public-input", { mode: 0o444 });
    fs.writeFileSync(path.join(directory, "agent.mjs"), `
      import assert from 'node:assert/strict';
      import fs from 'node:fs';
      import net from 'node:net';
      assert(process.getuid() > 0);
      for (const key of ['AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'COMPONENT_HOST_ONLY_MARKER']) assert.equal(process.env[key], undefined);
      for (const name of ['/root/.aws', '/root/.ssh', '/var/run/docker.sock', '/run/docker.sock', '/Library/Keychains', '/Users/abhiramteja/.aws', '/Users/abhiramteja/Downloads/genuine-scan-main']) assert(!fs.existsSync(name));
      const status = fs.readFileSync('/proc/self/status', 'utf8');
      assert.match(status, /CapEff:\\s+0000000000000000/);
      assert.match(status, /NoNewPrivs:\\s+1/);
      assert.equal(fs.readFileSync('/inputs/marker', 'utf8'), 'reviewed-public-input');
      assert.throws(() => fs.writeFileSync('/inputs/marker', 'changed'));
      assert.throws(() => fs.writeFileSync('/host-escape', 'changed'));
      fs.writeFileSync('/work/disposable', 'ephemeral');
      const blocked = host => new Promise((resolve, reject) => {
        const socket = net.createConnection({ host, port: 80 });
        socket.setTimeout(500);
        socket.once('connect', () => { socket.destroy(); reject(new Error('Unexpected network access')); });
        socket.once('error', () => { socket.destroy(); resolve(); });
        socket.once('timeout', () => { socket.destroy(); resolve(); });
      });
      for (const host of ['169.254.169.254', '169.254.170.2', 'host.docker.internal', '1.1.1.1']) await blocked(host);
      process.stdout.write('ISOLATION_RUNTIME_PROBE=PASS\\n');
    `, { mode: 0o444 });
    const result = spawnSync("docker", terraformDockerArguments(fs.realpathSync(directory)), {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, AWS_PROFILE: "administrator-profile-sentinel", COMPONENT_HOST_ONLY_MARKER: "must-not-cross" },
      encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024,
    });
    assert.equal(result.status, 0, `Docker isolation probe failed: ${result.stderr}`);
    assert.equal(result.stdout, "ISOLATION_RUNTIME_PROBE=PASS\n");
    assert.equal(fs.readFileSync(path.join(directory, "marker"), "utf8"), "reviewed-public-input");
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test("real pinned Terraform and provider validate offline inside the isolated runner with the committed lock", { skip: process.env.COMPONENT_CONTAINER_TESTS !== "1", timeout: 360000 }, async () => {
  const inputs = await prepareIsolatedTerraformInputs();
  try {
    const result = spawnSync("docker", [...terraformDockerArguments(inputs.directory), inputs.manifestSha256, "validate"], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME }, encoding: "utf8", timeout: 180000, maxBuffer: 1024 * 1024,
    });
    assert.equal(result.status, 0, `Isolated backend-disabled validation failed: ${result.stderr}`);
    assert.deepEqual(JSON.parse(result.stdout), { type: "result", valid: true, manifestSha256: inputs.manifestSha256, terraformVersion: "1.15.8", providerVersion: "6.65.0" });
    const run = () => spawnSync("docker", [...terraformDockerArguments(inputs.directory), inputs.manifestSha256, "validate"], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME }, encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024,
    });
    const cli = path.join(inputs.directory, "terraform.rc"), original = fs.readFileSync(cli);
    fs.chmodSync(cli, 0o600); fs.writeFileSync(cli, 'provider_installation { dev_overrides { "hashicorp/aws" = "/work/alternate" } }');
    const override = run(); assert.equal(override.status, 1); assert.match(override.stderr, /input-authentication/); assert.equal(override.stdout, "");
    fs.writeFileSync(cli, original); fs.chmodSync(cli, 0o444);
    const provider = path.join(inputs.directory, Object.keys(inputs.manifest.files).find(name => name.startsWith("providers/")));
    fs.chmodSync(provider, 0o600); fs.writeFileSync(provider, "substituted binary archive");
    const replacement = run(); assert.equal(replacement.status, 1); assert.match(replacement.stderr, /input-authentication/); assert.equal(replacement.stdout, "");
  } finally { inputs.dispose(); }
});
