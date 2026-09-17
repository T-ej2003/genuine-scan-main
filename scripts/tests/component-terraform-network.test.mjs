import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { once } from "node:events";
import { createIsolatedTerraformProxy } from "../aws/component-terraform-network.mjs";

async function fixture(t) {
  const messages = [], failures = [];
  const proxy = await createIsolatedTerraformProxy({ send: value => messages.push(value), fail: error => failures.push(error) });
  t.after(() => proxy.close());
  const socket = net.createConnection({ host: "127.0.0.1", port: Number(new URL(proxy.url).port) });
  socket.on("error", () => {});
  t.after(() => socket.destroy());
  await once(socket, "connect");
  return { proxy, socket, messages, failures };
}
const tick = () => new Promise(resolve => setTimeout(resolve, 10));

test("container proxy relays only CONNECT TLS bytes through fixed semantic frames", async t => {
  const { proxy, socket, messages, failures } = await fixture(t);
  socket.write("CONNECT sts.eu-west-2.amazonaws.com:443 HTTP/1.1\r\nHost: sts.eu-west-2.amazonaws.com:443\r\n\r\n");
  await tick();
  assert.deepEqual(messages, [{ type: "open", id: 1, host: "sts.eu-west-2.amazonaws.com" }]);
  const ready = once(socket, "data"); proxy.receive({ type: "connected", id: 1 });
  assert.equal((await ready)[0].toString(), "HTTP/1.1 200 Connection Established\r\n\r\n");
  socket.write(Buffer.from([22, 3, 3, 0, 1])); await tick();
  assert.deepEqual(messages[1], { type: "data", id: 1, data: Buffer.from([22, 3, 3, 0, 1]).toString("base64") });
  const received = once(socket, "data"); proxy.receive({ type: "data", id: 1, data: Buffer.from("TLS response").toString("base64") });
  assert.equal((await received)[0].toString(), "TLS response");
  proxy.receive({ type: "closed", id: 1 });
  assert.deepEqual(failures, []);
});

for (const target of ["169.254.169.254:443", "169.254.170.2:443", "host.docker.internal:443", "localhost:443", "iam.amazonaws.com:80", "iam.amazonaws.com.attacker.invalid:443", "/var/run/docker.sock", "[::1]:443"]) {
  test(`container proxy rejects ${target} before relay`, async t => {
    const { socket, messages, failures } = await fixture(t);
    socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: rejected\r\n\r\n`);
    await tick(); assert.deepEqual(messages, []); assert.equal(failures.length, 1);
  });
}

test("plain HTTP cannot become a metadata or credential-provider request", async t => {
  const { socket, messages } = await fixture(t);
  const response = once(socket, "data");
  socket.write("GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n");
  assert.match((await response)[0].toString(), /^HTTP\/1.1 405/);
  assert.deepEqual(messages, []);
});

for (const message of [{ type: "exec", id: 1, command: "aws" }, { type: "connected", id: 0 }, { type: "data", id: 999, data: "" }]) {
  test(`unknown relay input fails closed: ${JSON.stringify(message)}`, async t => {
    const { proxy, messages, failures } = await fixture(t);
    proxy.receive(message); assert.equal(failures.length, 1); assert.deepEqual(messages, []);
  });
}
