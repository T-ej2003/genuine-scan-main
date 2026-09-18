// Runs inside the network-disabled container. Only CONNECT/TLS bytes cross its
// stdio boundary; the host relay independently enforces the destination list.
import assert from "node:assert/strict";
import http from "node:http";
import { assertTerraformRelayTarget } from "./component-terraform-isolation.mjs";

export async function createIsolatedTerraformProxy({ send, fail }) {
  const sockets = new Map();
  let sequence = 0, closed = false;
  const server = http.createServer((_request, response) => { response.writeHead(405); response.end(); });
  server.maxConnections = 64;
  const close = () => {
    closed = true;
    for (const socket of sockets.values()) socket.destroy();
    sockets.clear(); server.close();
  };
  const reject = () => { close(); fail(new Error("Isolated proxy rejected")); };
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("connect", (request, socket, head) => {
    try {
      assert(!closed && sockets.size < 64 && sequence < 4096);
      assert.equal(head.length, 0, "Unexpected pre-CONNECT bytes");
      const match = /^([a-z0-9.-]+):443$/.exec(request.url || ""); assert(match);
      const host = assertTerraformRelayTarget(match[1]);
      const id = ++sequence;
      socket.pause(); sockets.set(id, socket);
      socket.setTimeout(30000, () => socket.destroy());
      socket.on("error", () => socket.destroy());
      socket.on("data", bytes => {
        // Bound each frame independently of the operating system's read size.
        for (let offset = 0; offset < bytes.length; offset += 65536) send({ type: "data", id, data: bytes.subarray(offset, offset + 65536).toString("base64") });
      });
      socket.on("close", () => {
        if (sockets.delete(id) && !closed) send({ type: "close", id });
      });
      send({ type: "open", id, host });
    } catch { socket.destroy(); reject(); }
  });
  await new Promise((resolve, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolve);
  });
  const connected = new Set();
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close,
    receive(message) {
      try {
        assert(!closed && Number.isSafeInteger(message.id));
        const socket = sockets.get(message.id);
        // An already-closed local connection may still have relay data in
        // flight. Only previously allocated IDs may be discarded this way.
        assert(message.id > 0 && message.id <= sequence);
        if (message.type === "data") {
          assert.deepEqual(Object.keys(message).sort(), ["data", "id", "type"]);
          assert(connected.has(message.id));
          assert(typeof message.data === "string" && message.data.length <= 131072);
          const bytes = Buffer.from(message.data, "base64"); assert.equal(bytes.toString("base64"), message.data);
          if (socket) { assert(socket.writableLength < 1024 * 1024); socket.write(bytes); }
        } else {
          assert.deepEqual(Object.keys(message).sort(), ["id", "type"]);
          if (message.type === "connected") {
            assert(!connected.has(message.id)); connected.add(message.id);
            if (socket) { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); socket.resume(); }
          } else {
            assert.equal(message.type, "closed");
            sockets.delete(message.id); socket?.destroy();
          }
        }
      } catch { reject(); }
    },
  };
}
