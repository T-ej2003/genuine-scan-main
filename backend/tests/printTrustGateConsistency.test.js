const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const regularPrintSource = read("backend/src/controllers/print-job/createPrintJobHandler.ts");
const replacementPrintSource = read("backend/src/services/printReissueService.ts");
const connectorActionAuthSource = read("backend/src/services/localAgentRequestAuthService.ts");
const directBrowserConfirmSource = read("backend/src/controllers/print-job/directPrintConfirmationHandlers.ts");
const localAgentClaimSource = read("backend/src/controllers/printerAgentJobController.ts");
const printingSql = read("backend/src/rls-waves/session-c/c02/printingLifecycle.sql");

assert(
  regularPrintSource.includes("createPrintJobRecords"),
  "regular print creation must use the capability-bound creation transaction"
);
assert(
  printingSql.includes("PRINTER_ATTESTATION_STALE") &&
    printingSql.includes('pa."signatureValid"') &&
    printingSql.includes('pa."trustValid"') &&
    printingSql.includes('pa."expiresAt">now_at'),
  "regular and replacement creation must enforce fresh signed printer attestation in PostgreSQL"
);
assert(
  connectorActionAuthSource.includes("resolvePrintingConnectorIdentity"),
  "connector claim/ack/confirm auth must re-check the reviewed connector identity boundary"
);
assert(
  connectorActionAuthSource.includes("PRINTER_ATTESTATION_STALE"),
  "stale connector action trust must fail with PRINTER_ATTESTATION_STALE"
);
assert(
  localAgentClaimSource.includes("recordConnectorEvent"),
  "local-agent claims must use the exact connector lifecycle function"
);
assert(
  !directBrowserConfirmSource
    .slice(
      directBrowserConfirmSource.indexOf("export const confirmPrintJob"),
      directBrowserConfirmSource.indexOf("export const scanPrintJobSample")
    )
    .includes("confirmPrintItemDispatch("),
  "browser/operator confirmation must not mark labels physically printed"
);

console.log("print trust gate consistency contract tests passed");
