import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { terraformDockerArguments } from "../aws/component-terraform-isolation.mjs";

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
