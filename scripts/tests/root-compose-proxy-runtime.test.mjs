import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const run = (args, options = {}) => execFileSync("docker", args, { cwd: root, encoding: "utf8", stdio: "pipe", ...options }).trim();
const digest = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

test("root Compose reserves the trusted frontend IP and its adapter is restart-idempotent", () => {
  run(["info", "--format", "{{.ServerVersion}}"]);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-root-proxy-"));
  const project = `mscqr-root-proxy-${process.pid}`;
  const templates = path.join(directory, "templates");
  fs.mkdirSync(templates);
  fs.copyFileSync(path.join(root, "nginx.conf"), path.join(templates, "default.http.conf"));
  fs.copyFileSync(path.join(root, "nginx.https.conf"), path.join(templates, "default.https.conf"));
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
      app: { ipv4_address: 172.30.10.2 }
networks:
  app:
    ipam:
      config:
        - subnet: 172.30.10.0/28
          ip_range: 172.30.10.8/29
`);
  const compose = ["compose", "-p", project, "-f", path.join(directory, "compose.yml")];
  try {
    run([...compose, "up", "-d", "redis", "backend", "worker"]);
    const dynamicIps = ["redis", "backend", "worker"].map((service) => run([...compose, "exec", "-T", service, "hostname", "-i"]));
    assert(dynamicIps.every((ip) => ip !== "172.30.10.2"));
    run([...compose, "up", "-d", "frontend"]);
    assert.equal(run([...compose, "exec", "-T", "frontend", "hostname", "-i"]), "172.30.10.2");
    const first = [digest(path.join(templates, "default.http.conf")), digest(path.join(templates, "default.https.conf"))];
    run([...compose, "restart", "frontend"]);
    assert.deepEqual([digest(path.join(templates, "default.http.conf")), digest(path.join(templates, "default.https.conf"))], first);
    assert.equal(run([...compose, "ps", "--status", "running", "--services", "frontend"]), "frontend");

    fs.appendFileSync(path.join(templates, "default.http.conf"), "\nproxy_set_header X-Forwarded-For unexpected;\n");
    run([...compose, "restart", "frontend"]);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    assert.equal(run([...compose, "ps", "--status", "running", "--services", "frontend"]), "");
  } finally {
    spawnSync("docker", [...compose, "down", "--volumes", "--remove-orphans"], { cwd: root, stdio: "ignore" });
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
