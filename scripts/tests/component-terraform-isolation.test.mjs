import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { assertTerraformRelayTarget, assertPublicRelayAddress, createTerraformRelay, terraformDockerArguments, terraformExecution } from "../aws/component-terraform-isolation.mjs";

test("isolated executor uses pinned platform image, no network, read-only inputs and no host control mount", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-terraform-inputs-"));
  fs.chmodSync(directory, 0o700);
  try {
    const args = terraformDockerArguments(fs.realpathSync(directory));
    for (const value of ["--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=never"]) assert(args.includes(value));
    assert.equal(args.filter(value => value.startsWith("--mount=")).length, 1);
    assert(args.find(value => value.startsWith("--mount=")).endsWith(",target=/inputs,readonly"));
    assert(!args.some(value => /docker\.sock|\.aws|Keychain|--privileged|--pid=host|--device|--volume/.test(value)));
    assert.deepEqual(args.filter(value => value.startsWith("--env=")), ["HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "ftp_proxy", "all_proxy", "no_proxy"].map(key => `--env=${key}=`));
    assert(args.includes(terraformExecution.image));
    fs.chmodSync(directory, 0o777); assert.throws(() => terraformDockerArguments(fs.realpathSync(directory)));
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test("activation CI preloads the exact immutable image required by pull=never", () => {
  const workflow = fs.readFileSync(path.resolve(".github/workflows/authorize-component-infrastructure-activation.yml"), "utf8");
  assert(workflow.includes(`docker pull ${terraformExecution.image}`));
});

for (const host of ["169.254.169.254", "169.254.170.2", "localhost", "host.docker.internal", "metadata.google.internal", "sts.us-east-1.amazonaws.com", "sts.eu-west-2.amazonaws.com.attacker.invalid", "iam.amazonaws.com:80", "https://iam.amazonaws.com", "other.s3.eu-west-2.amazonaws.com", "/var/run/docker.sock"]) {
  test(`relay denies destination ${host}`, () => assert.throws(() => assertTerraformRelayTarget(host)));
}
for (const address of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "169.254.170.2", "100.100.100.200", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1", "203.0.113.1", "::1", "::ffff:127.0.0.1", "fe80::1"]) {
  test(`relay denies private/reserved DNS answer ${address}`, () => assert.throws(() => assertPublicRelayAddress(address)));
}
test("relay connects only numeric validated public addresses on TLS port without credentials or commands", async () => {
  const writes = [], sends = [], calls = [];
  const socket = new EventEmitter();
  Object.assign(socket, { writableLength: 0, setTimeout: () => {}, destroy: () => {}, write: bytes => writes.push(bytes) });
  const relay = createTerraformRelay({ send: value => sends.push(value), fail: error => { throw error; },
    lookup: async (host, options) => { assert.equal(host, "sts.eu-west-2.amazonaws.com"); assert.deepEqual(options, { family: 4 }); return { address: "52.95.0.1" }; },
    connect: options => { calls.push(options); return socket; } });
  await relay.receive({ type: "open", id: 1, host: "sts.eu-west-2.amazonaws.com" });
  assert.deepEqual(calls, [{ host: "52.95.0.1", port: 443, family: 4 }]);
  socket.emit("connect");
  await relay.receive({ type: "data", id: 1, data: Buffer.from("opaque TLS").toString("base64") });
  assert.equal(writes[0].toString(), "opaque TLS");
  assert.deepEqual(sends, [{ type: "connected", id: 1 }]); relay.close();
});
test("DNS rebinding to metadata fails before opening a host socket", async () => {
  let failed = false;
  const relay = createTerraformRelay({ send: () => assert.fail(), fail: () => { failed = true; }, lookup: async () => ({ address: "169.254.169.254" }), connect: () => assert.fail() });
  await relay.receive({ type: "open", id: 1, host: "sts.eu-west-2.amazonaws.com" }); assert(failed);
});
for (const message of [{ type: "exec", id: 1, command: "aws" }, { type: "open", id: 1, host: "iam.amazonaws.com", port: 22 }, { type: "open", id: -1, host: "iam.amazonaws.com" }, { type: "data", id: 1, data: "not base64" }]) {
  test(`malformed child protocol cannot become host execution: ${JSON.stringify(message)}`, async () => {
    let failed = false;
    const relay = createTerraformRelay({ send: () => assert.fail(), fail: () => { failed = true; }, lookup: () => assert.fail(), connect: () => assert.fail() });
    await relay.receive(message); assert(failed);
  });
}
