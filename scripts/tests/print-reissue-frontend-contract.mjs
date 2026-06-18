import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const readSource = (relativePath) => readFileSync(join(process.cwd(), relativePath), "utf8");

const batchesPage = readSource("src/features/batches/BatchesPage.tsx");
const apiClient = readSource("src/lib/api/internal-client-printing-operations.ts");
const dialog = readSource("src/components/batches/LicenseeBatchWorkspaceDialog.tsx");

const approvalHandlerStart = batchesPage.indexOf("const decideReissueRequest");
const approvalHandlerEnd = batchesPage.indexOf("const printApprovedReissueRequest");
const approvalHandler = batchesPage.slice(approvalHandlerStart, approvalHandlerEnd);

assert.match(apiClient, /\/manufacturer\/print-reissue-requests\/\$\{encodeURIComponent\(requestId\)\}\/print/);
assert.match(apiClient, /print-approved-reissue/);
assert.match(batchesPage, /status: isManufacturer \? "APPROVED" : "PENDING"/);
assert.match(batchesPage, /apiClient\.printApprovedReissueRequest\(requestId\)/);
assert.match(batchesPage, /Printer verification expired\. Refresh printer status before printing\./);
assert.match(batchesPage, /onOpenExistingPrintProgress/);

assert.match(dialog, /Replacement labels ready/);
assert.match(dialog, /Print replacement labels/);
assert.match(dialog, /Refresh printer status/);
assert.match(dialog, /Ready to print/);

assert.doesNotMatch(approvalHandler, /Printer verification expired/);
assert.doesNotMatch(approvalHandler, /PRINTER_ATTESTATION_STALE/);
assert.match(approvalHandler, /Replacement labels are approved and ready for the manufacturer to print\./);

console.log("print reissue frontend lifecycle contract tests passed");
