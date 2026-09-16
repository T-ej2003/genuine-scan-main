import assert from "node:assert/strict";
import { test } from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../../", import.meta.url));
const mock = (file, exports) => {
  const id = require.resolve(path.join(root, "backend/dist", file));
  require.cache[id] = { id, filename: id, loaded: true, exports };
};
mock("config/database", { __esModule: true, default: {} });
mock("services/auth/authService", { getAdminStepUpWindowMinutes: () => 15 });
mock("services/auditService", {});

test("actual frontend serializers satisfy unchanged backend scope/purpose authority", async () => {
  const browserChannel = globalThis.BroadcastChannel;
  globalThis.BroadcastChannel = undefined;
  const previousConfig = process.env.TSX_TSCONFIG_PATH;
  process.env.TSX_TSCONFIG_PATH = path.join(root, "tsconfig.app.json");
  const unregister = require("tsx/cjs/api").register();
  try {
    // Only the browser transport is replaced; serializers and backend authority are real source.
    const transport = require.resolve(path.join(root, "src/lib/api/internal-client-core.ts"));
    require.cache[transport] = { id: transport, filename: transport, loaded: true, exports: { BASE_URL: "/api" } };
    const { createAdminOpsApi } = require(path.join(root, "src/lib/api/internal-client-admin-ops.ts"));
    let serialized;
    const api = createAdminOpsApi({ request: async (url) => { serialized = url; return { success: true, data: [] }; } });
    for (const [call, module, name] of [
      [api.getAuditLogs, "auditLogQueryService", "buildAuditLogBoundary"],
      [api.getFraudReports, "fraudReportQueryService", "buildFraudReportBoundary"],
      [api.getTraceTimeline, "traceEventService", "buildTraceTimelineBoundary"],
    ]) {
      await call({ licenseeId: "11111111-1111-4111-8111-111111111111", purpose: "contract regression review", limit: 1, offset: 0 });
      const query = Object.fromEntries(new URL(serialized, "https://fixture.invalid").searchParams);
      query.limit = Number(query.limit); query.offset = Number(query.offset); query.status = "ALL";
      const build = require(path.join(root, "backend/dist/services", module))[name];
      const user = { userId: "actor", role: "SUPER_ADMIN", sessionStage: "ACTIVE", authAssurance: "ADMIN_MFA", mfaVerifiedAt: new Date().toISOString() };
      const result = build(user, query, "request");
      assert.equal((result.context || result).licenseeId, query.licenseeId);
      assert.throws(() => build(user, { ...query, purpose: "" }, "request"));
      assert.throws(() => build(user, { ...query, licenseeId: "" }, "request"));
      assert.throws(() => build({ ...user, authAssurance: "PASSWORD" }, query, "request"));
      assert.throws(() => build({ ...user, role: "LICENSEE_ADMIN", licenseeId: "foreign-tenant" }, query, "request"));
    }
  } finally {
    unregister(); globalThis.BroadcastChannel = browserChannel;
    if (previousConfig === undefined) delete process.env.TSX_TSCONFIG_PATH;
    else process.env.TSX_TSCONFIG_PATH = previousConfig;
  }
});
