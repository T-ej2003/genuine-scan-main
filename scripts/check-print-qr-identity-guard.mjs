import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const printScanPaths = [
  "backend/src/services/printPayloadService.ts",
  "backend/src/services/printJobCreationTransactionService.ts",
  "backend/src/services/printLifecycleService.ts",
  "backend/src/services/localAgentClaimService.ts",
  "backend/src/services/networkDirectPrintService.ts",
  "backend/src/services/networkIppPrintService.ts",
  "backend/src/services/printReissueService.ts",
  "backend/src/services/printSampleScanService.ts",
  "backend/scripts/mscqr-print-test.ts",
];
const publicVerifyScanPaths = [
  "backend/src/controllers/verify/verificationHandlers.ts",
  "backend/src/controllers/publicController.ts",
];

const forbidden = [
  { label: "verify URL must not use displayCode", pattern: /\/verify\/\$\{[^}]*displayCode/i },
  { label: "verify URL must not use serial", pattern: /\/verify\/\$\{[^}]*(serial|labelSerial)/i },
  { label: "verify URL must not use placeholder serials", pattern: new RegExp(String.raw`/verify/[^"'\n` + "`" + String.raw`]*T` + "BD", "i") },
  { label: "print identity must not fall back from displayCode to code", pattern: /code:\s*[^,\n]*displayCode\s*\|\|\s*[^,\n]*code/i },
  { label: "print identity must not fall back from serialNumber to code", pattern: /serialNumber\s*\|\|\s*[^,\n]*code/i },
  { label: "print payload must not use display-code public-code fallback", pattern: /displayCode\s*\|\|\s*[^,\n]*code/i },
];
const publicVerifyForbidden = [
  { label: "public verify lookup must not query displayCode", pattern: /qRCode\.(findUnique|findFirst|findMany)\([\s\S]{0,220}where:\s*\{[\s\S]{0,120}displayCode/i },
  { label: "public verify lookup must not query serial fields", pattern: /qRCode\.(findUnique|findFirst|findMany)\([\s\S]{0,220}where:\s*\{[\s\S]{0,120}(serial|labelSerial|humanSerial)/i },
];

const failures = [];
for (const relativePath of printScanPaths) {
  const absolutePath = path.join(root, relativePath);
  if (!fs.existsSync(absolutePath)) continue;
  const content = fs.readFileSync(absolutePath, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(content)) {
      failures.push(`${relativePath}: ${rule.label}`);
    }
  }
}
for (const relativePath of publicVerifyScanPaths) {
  const absolutePath = path.join(root, relativePath);
  if (!fs.existsSync(absolutePath)) continue;
  const content = fs.readFileSync(absolutePath, "utf8");
  for (const rule of publicVerifyForbidden) {
    if (rule.pattern.test(content)) failures.push(`${relativePath}: ${rule.label}`);
  }
}

if (failures.length > 0) {
  console.error("Unsafe public QR identity patterns found:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("print QR identity guard passed");
