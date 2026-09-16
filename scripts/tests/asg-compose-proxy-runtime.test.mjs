import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateAsgNetworkContract } from "../dr/asg-network-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const run = (args, options = {}) => execFileSync("docker", args, { cwd: root, encoding: "utf8", stdio: "pipe", ...options }).trim();

test("ASG Compose excludes the pinned frontend proxy from real dynamic allocation", () => {
  run(["info", "--format", "{{.ServerVersion}}"]);
  assert.doesNotThrow(() => validateAsgNetworkContract({ subnet: "172.30.0.0/29", dynamicRange: "172.30.0.4/30", frontendIp: "172.30.0.2", trustedCidr: "172.30.0.2/32" }));
  assert.throws(() => validateAsgNetworkContract({ subnet: "172.30.0.0/29", dynamicRange: "172.30.0.0/29", frontendIp: "172.30.0.2", trustedCidr: "172.30.0.2/32" }));
  assert.throws(() => validateAsgNetworkContract({ subnet: "172.30.0.0/29", dynamicRange: "172.30.0.4/31", frontendIp: "172.30.0.2", trustedCidr: "172.30.0.2/32" }));
  assert.throws(() => validateAsgNetworkContract({ subnet: "172.30.0.0/29", dynamicRange: "172.30.0.4/30", frontendIp: "172.30.1.2", trustedCidr: "172.30.1.2/32" }));
  assert.throws(() => validateAsgNetworkContract({ subnet: "172.30.0.0/29", dynamicRange: "172.30.0.4/30", frontendIp: "172.30.0.2", trustedCidr: "172.30.0.0/24" }));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-asg-proxy-"));
  const project = `mscqr-asg-proxy-${process.pid}`;
  const composePath = path.join(directory, "compose.yml");
  fs.writeFileSync(composePath, `services:
  backend:
    image: alpine:3.22
    command: ["sleep", "300"]
    networks: [app]
  frontend:
    image: alpine:3.22
    command: ["sleep", "300"]
    networks:
      app:
        ipv4_address: 172.30.0.2
networks:
  app:
    ipam:
      config:
        - subnet: 172.30.0.0/29
          ip_range: 172.30.0.4/30
`);
  const compose = ["compose", "-p", project, "-f", composePath];
  try {
    run([...compose, "up", "-d", "backend"]);
    const backendIp = run([...compose, "exec", "-T", "backend", "hostname", "-i"]);
    assert.notEqual(backendIp, "172.30.0.2");
    run([...compose, "up", "-d", "frontend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), "172.30.0.2");
    assert.notEqual(backendIp, "172.30.0.2");
  } finally {
    spawnSync("docker", [...compose, "down", "--volumes", "--remove-orphans"], { cwd: root, stdio: "ignore" });
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
