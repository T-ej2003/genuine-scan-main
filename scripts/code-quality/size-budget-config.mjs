export const DEFAULT_BUDGETS = [
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

export const LEGACY_FILE_BUDGETS = {
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
    maxLines: 540,
    reason: "Post-scan verification now runs through a dedicated service, but the controller still centralizes entry-path responses and legacy verify routes.",
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
  "src/pages/ConnectorDownload.tsx": { label: "Legacy page", maxLines: 880 },
  "src/pages/PrinterDiagnostics.tsx": { label: "Legacy page", maxLines: 1620 },
  "src/pages/PrinterSetup.tsx": { label: "Legacy page", maxLines: 980 },
};
