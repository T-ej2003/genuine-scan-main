import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

// TLS for the existing disposable tmpfs harness, not a new database or a
// production configuration path. No endpoint, SQL or certificate input exists.
const container = "mscqr-p2-auth-security-postgres";
const docker = (args) => execFileSync("docker", args, { encoding: "utf8", timeout: 15000, stdio: ["ignore", "pipe", "pipe"] }).trim();
const [instance] = JSON.parse(docker(["inspect", container]));
assert.equal(instance.Config.Labels["com.docker.compose.project"], "mscqr-p2-auth-security");
assert.equal(instance.Config.Labels["com.docker.compose.service"], "p2-postgres");
assert.equal(instance.Config.Image, "postgres:18.4");
assert.ok(Object.hasOwn(instance.HostConfig.Tmpfs, "/var/lib/postgresql"));
assert.deepEqual(instance.HostConfig.PortBindings["5432/tcp"], [{ HostIp: "127.0.0.1", HostPort: "55432" }]);
assert.equal(process.argv.length, 2, "The disposable TLS setup accepts no arguments");
const sql = (statement) => docker(["exec", container, "psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-U", "mscqr_p2_test", "-d", "mscqr_p2_admin_test", "-c", statement]);
if (sql("SHOW ssl") !== "on") {
  assert.equal(sql("SHOW ssl_cert_file"), "server.crt", "Do not replace customized TLS configuration");
  assert.equal(sql("SHOW ssl_key_file"), "server.key", "Do not replace customized TLS configuration");
  const directory = docker(["exec", "--user", "postgres", container, "mktemp", "-d", "/tmp/mscqr-app-only-test-tls.XXXXXXXX"]);
  assert.match(directory, /^\/tmp\/mscqr-app-only-test-tls\.[A-Za-z0-9]{8}$/);
  docker(["exec", "--user", "postgres", container, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", `${directory}/server.key`, "-out", `${directory}/server.crt`]);
  docker(["exec", "--user", "postgres", container, "chmod", "600", `${directory}/server.key`]);
  sql(`ALTER SYSTEM SET ssl_cert_file='${directory}/server.crt'`);
  sql(`ALTER SYSTEM SET ssl_key_file='${directory}/server.key'`);
  sql("ALTER SYSTEM SET ssl=on");
  assert.equal(sql("SELECT pg_reload_conf()"), "t");
  for (let attempt = 0; attempt < 20 && sql("SHOW ssl") !== "on"; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
assert.equal(sql("SHOW ssl"), "on");
console.log("Disposable P2 PostgreSQL TLS enabled; no restart or production access.");
