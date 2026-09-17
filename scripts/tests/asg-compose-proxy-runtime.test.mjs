import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateAsgNetworkContract, validateDockerBridgeNetworkContract } from "../dr/asg-network-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const run = (args, options = {}) => execFileSync("docker", args, { cwd: root, encoding: "utf8", stdio: "pipe", ...options }).trim();

test("ASG Compose excludes the pinned frontend proxy from real dynamic allocation", () => {
  run(["info", "--format", "{{.ServerVersion}}"]);
  const asg = { subnet: "172.30.0.0/29", gateway: "172.30.0.1", dynamicRange: "172.30.0.4/30", frontendIp: "172.30.0.2", trustedCidr: "172.30.0.2/32" };
  assert.doesNotThrow(() => validateAsgNetworkContract(asg));
  for (const frontendIp of ["172.30.0.0", "172.30.0.1", "172.30.0.7", "172.30.0.4", "172.30.1.2"])
    assert.throws(() => validateAsgNetworkContract({ ...asg, frontendIp, trustedCidr: `${frontendIp}/32` }));
  assert.throws(() => validateAsgNetworkContract({ ...asg, dynamicRange: "172.30.0.0/29" }));
  assert.throws(() => validateAsgNetworkContract({ ...asg, dynamicRange: "172.30.0.4/31", dynamicServiceCount: 3 }));
  assert.throws(() => validateAsgNetworkContract({ ...asg, trustedCidr: "172.30.0.0/24" }));
  const rootConfig = { subnet: "172.30.10.0/28", gateway: "172.30.10.1", dynamicRange: "172.30.10.8/29", frontendIp: "172.30.10.2", trustedCidr: "172.30.10.2/32", prefix: "ROOT" };
  assert.doesNotThrow(() => validateDockerBridgeNetworkContract(rootConfig));
  for (const frontendIp of ["172.30.10.0", "172.30.10.1", "172.30.10.15", "172.30.10.8", "172.30.11.2"])
    assert.throws(() => validateDockerBridgeNetworkContract({ ...rootConfig, frontendIp, trustedCidr: `${frontendIp}/32` }));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-asg-proxy-"));
  const project = `mscqr-asg-proxy-${process.pid}`;
  const composePath = path.join(directory, "compose.yml");
  const testSubnet = `198.18.${20 + (process.pid % 200)}.0/29`;
  const testPrefix = testSubnet.slice(0, testSubnet.lastIndexOf("."));
  const testGateway = `${testPrefix}.1`;
  const testFrontend = `${testPrefix}.2`;
  const testRange = `${testPrefix}.4/30`;
  assert.doesNotThrow(() => validateAsgNetworkContract({ subnet: testSubnet, gateway: testGateway, dynamicRange: testRange, frontendIp: testFrontend, trustedCidr: `${testFrontend}/32` }));
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
        ipv4_address: ${testFrontend}
networks:
  app:
    ipam:
      config:
        - subnet: ${testSubnet}
          gateway: ${testGateway}
          ip_range: ${testRange}
`);
  const compose = ["compose", "-p", project, "-f", composePath];
  try {
    run([...compose, "up", "-d", "backend"]);
    const networkId = run(["network", "ls", "--filter", `name=${project}_app`, "--format", "{{.ID}}"]).split("\n")[0];
    assert.equal(JSON.parse(run(["network", "inspect", networkId]))[0].IPAM.Config[0].Gateway, testGateway);
    const backendIp = run([...compose, "exec", "-T", "backend", "hostname", "-i"]);
    assert.notEqual(backendIp, testFrontend);
    for (const forbiddenIp of [`${testPrefix}.0`, testGateway, `${testPrefix}.7`]) {
      const denied = spawnSync("docker", ["run", "--rm", "--network", `${project}_app`, "--ip", forbiddenIp, "alpine:3.22", "true"], { cwd: root, encoding: "utf8" });
      assert.notEqual(denied.status, 0, `${forbiddenIp} must not be assignable`);
    }
    run([...compose, "up", "-d", "frontend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), testFrontend);
    assert.notEqual(backendIp, testFrontend);
    run([...compose, "restart", "frontend", "backend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), testFrontend);
    assert.notEqual(run([...compose, "exec", "-T", "backend", "hostname", "-i"]), testFrontend);
  } finally {
    spawnSync("docker", [...compose, "down", "--volumes", "--remove-orphans"], { cwd: root, stdio: "ignore" });
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
