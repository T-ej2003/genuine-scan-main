const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const workflowSource = read("backend/src/services/printReissueRequestWorkflowService.ts");
const controllerSource = read("backend/src/controllers/print-job/queryHandlers.ts");
const routeSource = read("backend/src/routes/index.ts");

const decideBody = workflowSource.slice(
  workflowSource.indexOf("export const decideScopedPrintReissueRequest"),
  workflowSource.indexOf("export const startApprovedPrintReissueRequest")
);
const startBody = workflowSource.slice(workflowSource.indexOf("export const startApprovedPrintReissueRequest"));

assert(decideBody.includes("status: ReissueRequestStatus.APPROVED"), "approval must transition to APPROVED/ready-to-print");
assert(!decideBody.includes("createAuthorizedPrintReissue("), "approval must not create replacement print work");
assert(!decideBody.includes("replacementPrintJobId: result.replacementPrintJobId"), "approval audit must not depend on replacement job creation");
assert(decideBody.includes("readyToPrint: true"), "approval audit should record ready-to-print business decision");

assert(startBody.includes("isManufacturerRole(params.scope.role)"), "only manufacturer roles should start approved replacement printing");
assert(startBody.includes("request.requestedByUserId !== params.scope.userId"), "cross-manufacturer print start must be blocked");
assert(startBody.includes("status === ReissueRequestStatus.EXECUTED"), "print start must be idempotent after execution");
assert(startBody.includes("status !== ReissueRequestStatus.APPROVED"), "print start must require an approved request");
assert(startBody.includes("approvedReissueRequestId: request.id"), "print start must materialize work against the approved request");
assert(startBody.includes("PRINT_REISSUE_PRINT_BLOCKED"), "stale printer print-start failures must be audited");

assert(controllerSource.includes("PRINTER_ATTESTATION_STALE"), "stale printer response must use a typed safe code");
assert(controllerSource.includes("Printer verification expired. Refresh printer status before printing."), "stale printer response must use recovery copy");
assert(controllerSource.includes("res.status(409).json"), "stale printer response must be controlled non-500");

const printRoutePathIndex = routeSource.indexOf('"/manufacturer/print-reissue-requests/:id/print"');
const printRoute = routeSource.slice(
  routeSource.lastIndexOf("protectedMutationRouter.post", printRoutePathIndex),
  routeSource.indexOf(");", printRoutePathIndex)
);
assert(printRoute.includes("printMutationRouteLimiter"), "print-start route must keep print mutation rate limiting");
assert(printRoute.includes("requireRecentSensitiveAuth"), "print-start route must keep sensitive auth");
assert(printRoute.includes("enforceTenantIsolation"), "print-start route must keep tenant isolation");
assert(printRoute.includes("requireCsrf"), "print-start route must keep CSRF protection");

console.log("print reissue lifecycle separation contract tests passed");
