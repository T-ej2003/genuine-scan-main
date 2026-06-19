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

assert(
  regularPrintSource.includes("ensureSelectedPrinterReady"),
  "regular print creation must use the canonical secure printer readiness gate"
);
assert(
  replacementPrintSource.includes("ensureSelectedPrinterReady"),
  "replacement print creation must use the same secure printer readiness gate as regular print"
);
assert(
  connectorActionAuthSource.includes("getPrinterConnectionStatusForUser"),
  "connector claim/ack/confirm auth must re-check current trusted connector state"
);
assert(
  connectorActionAuthSource.includes("PRINTER_ATTESTATION_STALE"),
  "stale connector action trust must fail with PRINTER_ATTESTATION_STALE"
);
assert(
  localAgentClaimSource.includes("manufacturerId: registration.userId"),
  "local-agent claim selection must stay scoped to the trusted registration manufacturer"
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
