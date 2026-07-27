const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "../src");
const controller = readFileSync(path.join(root, "controllers/supportController.ts"), "utf8");
const repository = readFileSync(path.join(root, "rls-waves/session-b/b03/repositoryFunctions.ts"), "utf8");
const sql = readFileSync(path.join(root, "rls-waves/session-b/b03/b03AuthenticatedFunctions.sql"), "utf8");

for (const name of [
  "b03_list_support_tickets",
  "b03_get_support_ticket",
  "b03_update_support_ticket",
  "b03_add_support_ticket_message",
]) {
  assert.match(repository, new RegExp(`app_rls\\.${name}\\(`));
  assert.match(sql, new RegExp(`CREATE OR REPLACE FUNCTION app_rls\\.${name}\\(`));
}

assert.match(controller, /b03BoundaryForRequest\(req,\s*"support-ticket-read"\)/);
assert.match(controller, /b03BoundaryForRequest\(req,\s*"support-ticket-update"\)/);
assert.match(controller, /b03BoundaryForRequest\(req,\s*"support-ticket-message"\)/);
assert.doesNotMatch(controller, /withB02AuthenticatedRequest|listSupportTicketRows|loadSupportTicketRow/);
assert.match(sql, /actor\.role NOT IN \('SUPER_ADMIN','PLATFORM_SUPER_ADMIN'\)/);
assert.match(sql, /require_recent_mfa_session\([\s\S]*clock_timestamp\(\)::timestamp without time zone,30/);
assert.match(sql, /SUPPORT_TICKET_UPDATED[\s\S]*SUPPORT_TICKET_MESSAGE_ADDED/);
assert.doesNotMatch(sql, /SELECT\s+t\.\*|RETURNING\s+\*/i);
const messageFunction = sql.slice(
  sql.indexOf("CREATE OR REPLACE FUNCTION app_rls.b03_add_support_ticket_message"),
  sql.indexOf("REVOKE ALL ON FUNCTION app_rls.b03_require_authenticated_actor")
);
assert.doesNotMatch(messageFunction, /FROM public\."SupportTicket"[\s\S]*FOR UPDATE/);

console.log("support ticket capability boundary contract passed");
