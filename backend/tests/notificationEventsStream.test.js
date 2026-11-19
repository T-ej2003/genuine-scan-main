const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const path = require("node:path");
const { NotificationAudience, UserRole } = require("@prisma/client");

const dist = path.resolve(__dirname, "../dist");
const mockModule = (name, exportsValue) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let listener = null;
let reads = 0;
let activeReads = 0;
let maxActiveReads = 0;
let releaseInitial;
const initial = new Promise((resolve) => { releaseInitial = resolve; });
mockModule("services/manufacturerScopeService.js", { resolveAccessibleLicenseeIdsForUser: async () => ["licensee-a"] });
mockModule("rls-waves/session-b/b03/requestBoundary.js", { b03BoundaryForRequest: () => ({}) });
mockModule("services/notificationService.js", {
  listNotificationsForUser: async () => {
    reads += 1;
    activeReads += 1;
    maxActiveReads = Math.max(maxActiveReads, activeReads);
    try {
      if (reads === 1) return await initial;
      return { notifications: [{ id: `row-${reads}` }], unread: reads, total: reads };
    } finally {
      activeReads -= 1;
    }
  },
  onNotificationEvent: (callback) => {
    listener = callback;
    return () => { listener = null; };
  },
});
mockModule("services/notificationVisibility.js", { canRoleViewNotificationType: () => true });
const { notificationEvents } = require("../dist/controllers/notificationEventsController");

const waitFor = async (condition) => {
  const deadline = Date.now() + 1_000;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for notification stream");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
};

(async () => {
  const req = new EventEmitter();
  req.user = { userId: "actor-a", role: UserRole.MANUFACTURER_ADMIN, licenseeId: "licensee-a", orgId: "org-a" };
  req.query = { limit: "8" };
  const writes = [];
  const res = new EventEmitter();
  res.setHeader = () => undefined;
  res.flushHeaders = () => undefined;
  res.write = (chunk) => { writes.push(String(chunk)); return true; };
  res.end = () => res.emit("close");
  res.status = () => res;
  const running = notificationEvents(req, res);
  await waitFor(() => listener && reads === 1);
  listener({ type: "created", audience: NotificationAudience.MANUFACTURER, licenseeId: "foreign" });
  listener({ type: "created", audience: NotificationAudience.MANUFACTURER, licenseeId: "licensee-a" });
  listener({ type: "read", audience: NotificationAudience.MANUFACTURER, licenseeId: "licensee-a" });
  assert.equal(reads, 1, "events during the initial snapshot must be queued");
  releaseInitial({ notifications: [{ id: "old" }], unread: 0, total: 1 });
  await running;
  await waitFor(() => reads === 2);
  assert.equal(maxActiveReads, 1, "snapshots must never run concurrently");
  const snapshots = writes.filter((chunk) => chunk.includes('"type":"snapshot"'));
  assert.equal(snapshots.length, 2, "events during initial load must cause one authoritative resnapshot");
  assert(snapshots[0].includes('"id":"old"') && snapshots[1].includes('"id":"row-2"'));

  listener({ type: "created", audience: NotificationAudience.MANUFACTURER, licenseeId: "licensee-a" });
  listener({ type: "read", audience: NotificationAudience.MANUFACTURER, licenseeId: "licensee-a" });
  await waitFor(() => reads === 3);
  assert.equal(reads, 3, "a burst of committed events must use one governed read");
  res.end();
  assert.equal(listener, null, "closing the stream must release its event subscription");
  console.log("notification event stream tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
