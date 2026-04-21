import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();

const DEFAULT_BUDGETS = [
  {
    label: "Page",
    maxLines: 700,
    match: (filePath) =>
      (/^src\/pages\/.+\.tsx$/.test(filePath) || /^src\/features\/.+\/.+Page\.tsx$/.test(filePath)) &&
      !/src\/pages\/help\//.test(filePath),
  },
  {
    label: "Layout shell",
    maxLines: 500,
    match: (filePath) => /^src\/features\/.+\/.+Shell\.tsx$/.test(filePath),
  },
  {
    label: "Feature hook",
    maxLines: 700,
    match: (filePath) => /^src\/features\/.+\/use[A-Z].+\.(ts|tsx)$/.test(filePath),
  },
  {
    label: "Controller",
    maxLines: 500,
    match: (filePath) => /^backend\/src\/controllers\/.+\.ts$/.test(filePath),
  },
  {
    label: "Client",
    maxLines: 400,
    match: (filePath) => /^src\/lib\/api-client\.ts$/.test(filePath),
  },
  {
    label: "Transport module",
    maxLines: 700,
    match: (filePath) => /^src\/lib\/api\/internal-client-.+\.ts$/.test(filePath),
  },
];

const LEGACY_FILE_BUDGETS = {
  "backend/src/controllers/authController.ts": {
    label: "Legacy controller",
    maxLines: 1325,
    reason: "Auth controller still combines login, session, and recovery flows pending security-domain extraction.",
  },
  "backend/src/controllers/qrController.ts": { label: "Legacy controller", maxLines: 1760 },
  "backend/src/controllers/incidentController.ts": { label: "Legacy controller", maxLines: 900 },
  "backend/src/controllers/userController.ts": { label: "Legacy controller", maxLines: 820 },
  "backend/src/controllers/scanController.ts": { label: "Legacy controller", maxLines: 680 },
  "backend/src/controllers/licenseeController.ts": { label: "Legacy controller", maxLines: 650 },
  "backend/src/controllers/irIncidentController.ts": { label: "Legacy controller", maxLines: 760 },
  "backend/src/controllers/printerAgentJobController.ts": { label: "Legacy controller", maxLines: 680 },
  "backend/src/controllers/printerController.ts": { label: "Legacy controller", maxLines: 680 },
  "backend/src/controllers/printerGatewayController.ts": { label: "Legacy controller", maxLines: 1080 },
  "backend/src/controllers/verify/claimHandlers.ts": { label: "Legacy controller", maxLines: 580 },
  "backend/src/controllers/governanceController.ts": {
    label: "Legacy controller",
    maxLines: 560,
    reason: "Governance approval and compliance-pack endpoints remain consolidated pending service extraction.",
  },
  "backend/src/controllers/verify/verificationHandlers.ts": {
    label: "Legacy controller",
    maxLines: 1300,
    reason: "Public verification flow remains monolithic until the handler and policy orchestration split lands.",
  },
  "backend/src/controllers/verify/verifyPresentation.ts": {
    label: "Legacy controller",
    maxLines: 560,
    reason: "Verification presentation helpers still centralize public-proof messaging and readiness mapping.",
  },
  "src/features/layout/useManufacturerPrinterConnection.ts": { label: "Legacy feature hook", maxLines: 740 },
  "src/lib/api/internal-client-verify-support.ts": {
    label: "Legacy transport module",
    maxLines: 800,
    reason: "Verify support transport still consolidates customer auth, session, and ownership endpoints pending module split.",
  },
  "src/pages/AuditLogs.tsx": { label: "Legacy page", maxLines: 740 },
  "src/pages/AccountSettings.tsx": {
    label: "Legacy page",
    maxLines: 1080,
    reason: "Account settings still bundles profile, security, and device-management sections in one route component.",
  },
  "src/pages/ConnectorDownload.tsx": { label: "Legacy page", maxLines: 880 },
  "src/pages/Licensees.tsx": { label: "Legacy page", maxLines: 800 },
  "src/pages/PrinterDiagnostics.tsx": { label: "Legacy page", maxLines: 1620 },
  "src/pages/PrinterSetup.tsx": { label: "Legacy page", maxLines: 980 },
};

const WALK_ROOTS = ["src", "backend/src", "scripts"];

const walk = (directory) => {
  const absoluteDirectory = path.join(ROOT, directory);
  if (!fs.existsSync(absoluteDirectory)) return [];

  const result = [];
  for (const entry of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
    const absolutePath = path.join(absoluteDirectory, entry.name);
    const relativePath = path.relative(ROOT, absolutePath).replaceAll(path.sep, "/");
    if (entry.isDirectory()) {
      result.push(...walk(relativePath));
      continue;
    }
    result.push(relativePath);
  }
  return result;
};

const countLines = (filePath) => {
  const content = fs.readFileSync(path.join(ROOT, filePath), "utf8");
  return content.split("\n").length;
};

const resolveBudget = (filePath) => {
  if (LEGACY_FILE_BUDGETS[filePath]) return LEGACY_FILE_BUDGETS[filePath];
  return DEFAULT_BUDGETS.find((budget) => budget.match(filePath)) || null;
};

const filesToCheck = Array.from(new Set(WALK_ROOTS.flatMap(walk))).sort();

const violations = [];
const checked = [];

for (const filePath of filesToCheck) {
  const budget = resolveBudget(filePath);
  if (!budget) continue;

  const lines = countLines(filePath);
  checked.push({ filePath, lines, budget });
  if (lines > budget.maxLines) {
    violations.push({ filePath, lines, budget });
  }
}

if (violations.length > 0) {
  console.error("Code-size budget failures:");
  for (const violation of violations) {
    const reasonSuffix = violation.budget.reason ? ` [reason: ${violation.budget.reason}]` : "";
    console.error(
      `- ${violation.filePath}: ${violation.lines} lines exceeds ${violation.budget.maxLines} (${violation.budget.label})${reasonSuffix}`
    );
  }
  process.exit(1);
}

console.log(`Code-size budgets passed for ${checked.length} tracked files.`);
