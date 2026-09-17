import assert from "node:assert/strict";
import net from "node:net";
import dns from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";

export const terraformExecution = Object.freeze({
  image: "docker.io/library/node@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d",
  terraformVersion: "1.15.8", providerVersion: "6.65.0",
  archives: Object.freeze({
    amd64: Object.freeze({ terraform: "d25ce7b6902013ad905db3d2eab0be4cd905887fe88b81a6171b8d5503c31f3d", provider: "718a880d81bfd9af7e297ed3d7bf98d1febebe8b9ebe3333854a4c17f2c4de09" }),
    arm64: Object.freeze({ terraform: "8891e9dcedc9e3b8950bc6af9d4d8af1f4cfade3062f53b9dc403a89f6ce8c9c", provider: "8d571e06d78b91b28faa7fafee99dee920d4f7a50f07ec9cd21695a385bcc0d5" }),
  }),
});
const hosts = new Set([
  "sts.eu-west-2.amazonaws.com", "iam.amazonaws.com", "dynamodb.eu-west-2.amazonaws.com", "s3.eu-west-2.amazonaws.com",
  "mscqr-production-terraform-state-368992683803-eu-west-2.s3.eu-west-2.amazonaws.com",
]);

// With --network=none the only remote path is this bounded byte relay. It
// forwards TLS, does not terminate it, and never loads a credential provider.
// No socket/path/port/service supplied by the child becomes a host command.
export function assertTerraformRelayTarget(host) {
  assert(typeof host === "string" && hosts.has(host), "Unreviewed Terraform network destination");
  return host;
}
export function assertPublicRelayAddress(address) {
  // Request IPv4 deliberately: one small auditable set, not IPv4-mapped IPv6 or
  // link-local scope parsing. DNS answers are validated before numeric connect.
  assert.equal(net.isIP(address), 4);
  const [a, b, c] = address.split(".").map(Number);
  assert(a > 0 && a < 224 && ![10, 127].includes(a));
  assert(!(a === 100 && b >= 64 && b <= 127));
  assert(!(a === 169 && b === 254));
  assert(!(a === 172 && b >= 16 && b <= 31));
  assert(!(a === 192 && (b === 168 || b === 0 || b === 88 && c === 99)));
  assert(!(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)));
  assert(!(a === 203 && b === 0 && c === 113));
  return address;
}

export function terraformDockerArguments(inputDirectory) {
  assert(path.isAbsolute(inputDirectory));
  const actual = fs.realpathSync(inputDirectory);
  assert.equal(actual, inputDirectory, "Input directory must not be a symlink");
  const stat = fs.statSync(actual);
  assert(stat.isDirectory() && (stat.mode & 0o077) === 0 && stat.uid === process.getuid());
  const uid = process.getuid(), gid = process.getgid();
  assert(uid > 0 && gid >= 0, "Do not run isolated Terraform as root");
  assert.match(path.basename(actual), /^mscqr-component-terraform-inputs-[A-Za-z0-9]{6}$/);
  assert(!/[\r\n,]/.test(actual));
  const architecture = { x64: "amd64", arm64: "arm64" }[process.arch];
  assert(architecture, "Unsupported isolated execution architecture");
  return ["run", "--rm", "--interactive", "--pull=never", `--platform=linux/${architecture}`,
    "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    `--user=${uid}:${gid}`, "--pids-limit=128", "--memory=3g", "--cpus=2",
    `--tmpfs=/work:rw,nosuid,nodev,size=2147483648,uid=${uid},gid=${gid},mode=0700`,
    `--mount=type=bind,source=${actual},target=/inputs,readonly`,
    "--workdir=/work", "--entrypoint=node", terraformExecution.image, "/inputs/agent.mjs"];
}

// Only an authenticated source/package directory may be passed to the runner.
// The caller installs this relay on the container's stdio, never a listening
// host port or Docker socket. Protocol errors terminate the whole execution.
export function createTerraformRelay({ send, fail, lookup = dns.lookup, connect = net.createConnection }) {
  const sockets = new Map();
  const ids = new Set();
  let stopped = false;
  let pending = 0;
  const close = () => { stopped = true; for (const socket of sockets.values()) socket.destroy(); sockets.clear(); };
  const reject = () => { close(); fail(new Error("Isolated Terraform transport rejected")); };
  return {
    close,
    async receive(message) {
      try {
        assert(!stopped);
        assert(Number.isSafeInteger(message.id) && message.id > 0 && message.id <= 4096);
        if (message.type === "open") {
          assert.deepEqual(Object.keys(message).sort(), ["host", "id", "type"]);
          assert(!ids.has(message.id) && sockets.size + pending < 64);
          const host = assertTerraformRelayTarget(message.host);
          ids.add(message.id);
          pending++;
          const answer = await lookup(host, { family: 4 });
          pending--;
          assert(!stopped);
          const address = assertPublicRelayAddress(answer.address);
          const socket = connect({ host: address, port: 443, family: 4 });
          sockets.set(message.id, socket);
          socket.setTimeout(30000);
          socket.on("connect", () => send({ type: "connected", id: message.id }));
          socket.on("data", bytes => send({ type: "data", id: message.id, data: bytes.toString("base64") }));
          socket.on("error", () => socket.destroy());
          socket.on("timeout", () => socket.destroy());
          socket.on("close", () => { sockets.delete(message.id); if (!stopped) send({ type: "closed", id: message.id }); });
        } else if (message.type === "data") {
          assert.deepEqual(Object.keys(message).sort(), ["data", "id", "type"]);
          assert(typeof message.data === "string" && message.data.length <= 131072 && /^[A-Za-z0-9+/]*={0,2}$/.test(message.data));
          const bytes = Buffer.from(message.data, "base64");
          assert.equal(bytes.toString("base64"), message.data);
          const socket = sockets.get(message.id); assert(socket);
          assert(socket.writableLength < 1024 * 1024, "Relay backpressure limit");
          socket.write(bytes);
        } else {
          assert.equal(message.type, "close");
          assert.deepEqual(Object.keys(message).sort(), ["id", "type"]);
          assert(ids.has(message.id));
          sockets.get(message.id)?.destroy();
        }
      } catch { reject(); }
    },
  };
}
