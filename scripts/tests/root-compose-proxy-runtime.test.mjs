import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateDockerBridgeNetworkContract } from "../dr/asg-network-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const run = (args, options = {}) => execFileSync("docker", args, { cwd: root, encoding: "utf8", stdio: "pipe", ...options }).trim();
const digest = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

test("root Compose reserves the trusted frontend IP and its adapter is restart-idempotent", () => {
  run(["info", "--format", "{{.ServerVersion}}"]);
  const network = { subnet: "172.30.10.0/28", gateway: "172.30.10.1", dynamicRange: "172.30.10.8/29", frontendIp: "172.30.10.2", trustedCidr: "172.30.10.2/32", dynamicServiceCount: 3, prefix: "ROOT" };
  assert.doesNotThrow(() => validateDockerBridgeNetworkContract(network));
  for (const frontendIp of ["172.30.10.0", "172.30.10.1", "172.30.10.15", "172.30.10.8", "172.30.11.2"])
    assert.throws(() => validateDockerBridgeNetworkContract({ ...network, frontendIp, trustedCidr: `${frontendIp}/32` }));
  const testSubnet = `198.19.${20 + (process.pid % 200)}.0/28`;
  const testPrefix = testSubnet.slice(0, testSubnet.lastIndexOf("."));
  const testGateway = `${testPrefix}.1`;
  const testFrontend = `${testPrefix}.2`;
  const testRange = `${testPrefix}.8/29`;
  assert.doesNotThrow(() => validateDockerBridgeNetworkContract({ subnet: testSubnet, gateway: testGateway, dynamicRange: testRange, frontendIp: testFrontend, trustedCidr: `${testFrontend}/32`, dynamicServiceCount: 3, prefix: "ROOT" }));
  const fixture = (label, mutate) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), `mscqr-root-proxy-${label}-`));
    const templates = path.join(directory, "templates");
    fs.mkdirSync(templates);
    fs.copyFileSync(path.join(root, "nginx.conf"), path.join(templates, "default.http.conf"));
    fs.copyFileSync(path.join(root, "nginx.https.conf"), path.join(templates, "default.https.conf"));
    mutate?.(templates);
    fs.writeFileSync(path.join(directory, "canonical.sh"), "#!/bin/sh\nexec sleep 300\n", { mode: 0o755 });
    fs.writeFileSync(path.join(directory, "compose.yml"), `services:
  redis: { image: alpine:3.22, command: ["sleep", "300"], networks: [app] }
  backend: { image: alpine:3.22, command: ["sleep", "300"], networks: [app] }
  worker: { image: alpine:3.22, command: ["sleep", "300"], networks: [app] }
  frontend:
    image: alpine:3.22
    entrypoint: ["/root-adapter.sh"]
    volumes:
      - { type: bind, source: ${JSON.stringify(path.join(root, "docker/nginx-root-entrypoint.sh"))}, target: /root-adapter.sh, read_only: true }
      - { type: bind, source: ${JSON.stringify(path.join(directory, "canonical.sh"))}, target: /usr/local/bin/nginx-entrypoint.sh, read_only: true }
      - { type: bind, source: ${JSON.stringify(templates)}, target: /etc/nginx/templates }
    networks:
      app: { ipv4_address: ${testFrontend} }
networks:
  app:
    ipam:
      config:
        - subnet: ${testSubnet}
          gateway: ${testGateway}
          ip_range: ${testRange}
`);
    return { directory, templates };
  };
  const runFixture = (label, mutate, verify) => {
    const { directory, templates } = fixture(label, mutate);
    const project = `mscqr-root-proxy-${label}-${process.pid}`;
    const compose = ["compose", "-p", project, "-f", path.join(directory, "compose.yml")];
    try {
      verify({ compose, directory, templates, project });
    } finally {
      spawnSync("docker", [...compose, "down", "--volumes", "--remove-orphans"], { cwd: root, stdio: "ignore" });
      fs.rmSync(directory, { recursive: true, force: true });
    }
  };
  runFixture("valid", undefined, ({ compose, templates, project }) => {
    run([...compose, "up", "-d", "redis", "backend", "worker"]);
    const networkId = run(["network", "ls", "--filter", `name=${project}_app`, "--format", "{{.ID}}"]).split("\n")[0];
    assert.equal(JSON.parse(run(["network", "inspect", networkId]))[0].IPAM.Config[0].Gateway, testGateway);
    const dynamicIps = ["redis", "backend", "worker"].map((service) => run([...compose, "exec", "-T", service, "hostname", "-i"]));
    assert(dynamicIps.every((ip) => ip !== testFrontend));
    run([...compose, "up", "-d", "frontend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), testFrontend);
    for (const forbiddenIp of [`${testPrefix}.0`, testGateway, `${testPrefix}.15`]) {
      const denied = spawnSync("docker", ["run", "--rm", "--network", `${project}_app`, "--ip", forbiddenIp, "alpine:3.22", "true"], { cwd: root, encoding: "utf8" });
      assert.notEqual(denied.status, 0, `${forbiddenIp} must not be assignable`);
    }
    const first = [digest(path.join(templates, "default.http.conf")), digest(path.join(templates, "default.https.conf"))];
    run([...compose, "restart", "frontend"]);
    assert.deepEqual([digest(path.join(templates, "default.http.conf")), digest(path.join(templates, "default.https.conf"))], first);
    assert.equal(run([...compose, "ps", "--status", "running", "--services", "frontend"]), "frontend");
    run([...compose, "restart", "backend"]);
    assert.notEqual(run([...compose, "exec", "-T", "backend", "hostname", "-i"]), testFrontend);
    run([...compose, "down"]);
    run([...compose, "up", "-d", "redis", "backend", "worker", "frontend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), testFrontend);
  });
  runFixture("malformed", (templates) => fs.appendFileSync(path.join(templates, "default.http.conf"), "\nproxy_set_header X-Forwarded-For unexpected;\n"), ({ compose }) => {
    run([...compose, "up", "-d", "frontend"]);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    assert.equal(run([...compose, "ps", "--status", "running", "--services", "frontend"]), "");
  });
});
