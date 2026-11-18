const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const path = require("node:path");

const dist = path.resolve(__dirname, "../dist");
const mockModule = (name, exportsValue) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let auditListener;
let printListener;
let releaseInitial;
const initial = new Promise((resolve) => { releaseInitial = resolve; });
let snapshot = initial;
mockModule("services/auditService.js", { onAuditLog: (callback) => { auditListener = callback; return () => { auditListener = null; }; } });
mockModule("services/printJobRealtimeService.js", {
  onPrintJobRealtimeEvent: (callback) => { printListener = callback; return () => { printListener = null; }; },
  canUserReceivePrintJobEvent: (req, event) => req.user.licenseeId === event.licenseeId,
});
mockModule("services/dashboardSnapshotService.js", {
  getDashboardSnapshot: () => snapshot,
  canDeliverDashboardAuditDelta: async (req, licenseeId) => req.user.licenseeId === licenseeId,
});
const { dashboardEvents } = require("../dist/controllers/eventsController");

(async () => {
  const req = { user: { licenseeId: "tenant-a" } };
  const res = new EventEmitter();
  const writes = [];
  res.setHeader = () => undefined;
  res.flushHeaders = () => undefined;
  res.write = (chunk) => { writes.push(String(chunk)); return true; };
  res.status = () => res;
  res.end = () => res.emit("close");
  const running = dashboardEvents(req, res);
  assert(printListener && auditListener, "subscriptions must be established before the initial snapshot read");
  printListener({ licenseeId: "tenant-a", batchId: "batch-a", type: "print_job.created" });
  releaseInitial({ totalQRCodes: 1, activeLicensees: 1, manufacturers: 1, totalBatches: 1, qr: {} });
  await running;
  assert(writes.join("").includes('"reason":"initial_race"'), "a committed change during initial load must cause refresh");

  const count = () => writes.filter((chunk) => chunk.includes('"type":"summary.refresh"')).length;
  const before = count();
  printListener({ licenseeId: "tenant-b", batchId: "batch-b", type: "print_job.created" });
  assert.equal(count(), before, "other tenant print events must be filtered");
  printListener({ licenseeId: "tenant-a", batchId: "batch-a", type: "print_job.created" });
  assert.equal(count(), before + 1);
  req.user.role = "MANUFACTURER";
  await auditListener({ id: "audit-a", licenseeId: "tenant-a", entityType: "Batch", action: "ALLOCATED", details: { private: "audit-detail" } });
  assert.equal(count(), before + 2);
  assert(!writes.join("").includes("audit-detail"), "manufacturer dashboard must not receive audit details");
  req.user.role = "LICENSEE_ADMIN";
  await auditListener({ id: "audit-b", licenseeId: "tenant-a", entityType: "Batch", action: "ALLOCATED" });
  assert(writes.join("").includes('"type":"audit.delta"'));
  res.end();
  assert.equal(auditListener, null);
  assert.equal(printListener, null);

  snapshot = new Promise((resolve) => { releaseInitial = resolve; });
  const foreignWrites = [];
  const foreignRes = new EventEmitter();
  foreignRes.setHeader = res.setHeader;
  foreignRes.flushHeaders = res.flushHeaders;
  foreignRes.write = (chunk) => { foreignWrites.push(String(chunk)); return true; };
  foreignRes.status = () => foreignRes;
  foreignRes.end = () => foreignRes.emit("close");
  const foreignRunning = dashboardEvents({ user: { licenseeId: "tenant-a", role: "LICENSEE_ADMIN" } }, foreignRes);
  await auditListener({ id: "foreign-audit", licenseeId: "tenant-b", entityType: "Batch", action: "ALLOCATED" });
  releaseInitial({ totalQRCodes: 1, activeLicensees: 1, manufacturers: 1, totalBatches: 1, qr: {} });
  await foreignRunning;
  assert(!foreignWrites.join("").includes('"reason":"initial_race"'), "foreign tenant activity must not dirty the initial snapshot");
  foreignRes.end();
  console.log("dashboard event stream tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
