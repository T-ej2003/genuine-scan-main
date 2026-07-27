const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "../../../..");
const source = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const analytics = source("backend/src/services/analyticsRollupService.ts");
assert.match(analytics, /app_rls\.refresh_inventory_status_rollups/);
assert.match(analytics, /app_rls\.refresh_scan_metrics_hourly_rollups/);
assert.doesNotMatch(analytics, /prisma\.(?:inventoryStatusRollup|scanMetricsHourlyRollup|systemCheckpoint)\./);

const audit = source("backend/src/services/auditLogOutboxService.ts");
assert.match(audit, /consumeAuditLogOutbox\(tx/);
assert.match(audit, /failAuditLogOutbox\(tx/);
assert.match(audit, /B03 audit enqueue requires an attributed transaction and durable authority/);

const siem = source("backend/src/services/siemOutboxService.ts");
assert.match(siem, /"Idempotency-Key": row\.id/);
assert.match(siem, /completeSecurityEventOutbox\(tx/);
assert.match(siem, /failSecurityEventOutbox\(tx/);

const incident = source("backend/src/services/incidentEmailService.ts");
assert.match(incident, /requireB03AuthenticatedFunctionBoundary\(input\.databaseBoundary\)/);
assert.ok(
  incident.indexOf("requireB03AuthenticatedFunctionBoundary(input.databaseBoundary)") <
    incident.indexOf("sendMailSafely({"),
  "secure boundary validation must precede the external email side effect"
);

const notification = source("backend/src/services/notificationService.ts");
assert.match(notification, /createRoleNotificationsThroughBoundary/);
assert.match(notification, /createUserNotificationThroughBoundary/);
assert.match(notification, /resolveIncidentNotificationScope/);
assert.match(notification, /listNotificationsForUserThroughBoundary/);
assert.match(notification, /requireB03AuthenticatedFunctionBoundary/);

const attention = source("backend/src/services/attentionQueueService.ts");
assert.match(attention, /readAttentionQueueProjection/);
assert.doesNotMatch(attention, /prisma\.(?:incident|policyAlert|supportTicket|auditLog)\./);

const main = async () => {
  const previous = process.env.MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED;
  process.env.MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED = "true";
  const { sendIncidentEmail } = require("../../../dist/services/incidentEmailService");
  let databaseRuns = 0;
  await assert.rejects(sendIncidentEmail({
    incidentId: "incident-1",
    toAddress: "recipient@example.test",
    subject: "Incident",
    text: "Body",
    senderMode: "actor",
    actorUser: {
      email: "caller-asserted@example.test",
      name: "Caller asserted",
      role: "SUPER_ADMIN",
    },
    databaseBoundary: {
      requestId: "174d1fe7-f82e-42a7-829a-ddb8ecf329cb",
      run: async () => {
        databaseRuns += 1;
        throw new Error("database boundary should not run for a blank actor ID");
      },
    },
  }), /database-verified actor/);
  assert.equal(databaseRuns, 0, "blank actor claims must be denied before DB or email side effects");
  if (previous === undefined) delete process.env.MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED;
  else process.env.MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED = previous;
  console.log("B03 service activation tests passed");
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
