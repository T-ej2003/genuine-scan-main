const assert = require("node:assert/strict");
const path = require("node:path");
const { test } = require("node:test");
const dist = path.resolve(__dirname, "../dist");
const mock = (name, exports) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};

test("committed progress invalidation crosses instances without crossing tenant or manufacturer scope", async () => {
  const subscriptions = [];
  const modulePath = require.resolve(path.join(dist, "services/printJobRealtimeService"));
  mock("middleware/tenantIsolation", { getEffectiveLicenseeId: (req) => req.licenseeId });
  const load = (origin) => {
    mock("services/redisService", {
      getRedisInstanceId: () => origin,
      subscribeRedisJson: async (_channel, callback) => { subscriptions.push(callback); },
      publishRedisJson: async (_channel, payload) => { for (const listener of subscriptions) listener(payload); },
    });
    delete require.cache[modulePath];
    return require(modulePath);
  };
  const first = load("instance-a");
  const second = load("instance-b");
  const local = [], remote = [];
  const offFirst = first.onPrintJobRealtimeEvent((event) => local.push(event));
  const offSecond = second.onPrintJobRealtimeEvent((event) => remote.push(event));
  await first.publishPrintJobViewEvent({ printJobId: "job", manufacturerId: "maker-a",
    licenseeId: "tenant-a", batchId: "batch-a", type: "label_confirmed", reason: "printer_session_progress" });
  assert.equal(local.length, 1);
  assert.equal(remote.length, 1);
  const event = remote[0];
  assert.equal(second.canUserReceivePrintJobEvent({ user: { role: "LICENSEE_ADMIN", licenseeId: "tenant-b" } }, event), false);
  assert.equal(second.canUserReceivePrintJobEvent({ user: { role: "MANUFACTURER_ADMIN", userId: "maker-b" } }, event), false);
  assert.equal(second.canUserReceivePrintJobEvent({ user: { role: "MANUFACTURER_ADMIN", userId: "maker-a" } }, event), true);
  assert.equal(second.canUserReceivePrintJobEvent({ user: { role: "SUPER_ADMIN" }, licenseeId: "tenant-b" }, event), false);
  offFirst(); offSecond();
});
