import { buildVerifyUrl } from "./qrService";
import { readPrintingProjection } from "../rls-waves/session-c/c02/printingLifecycleRepository";

export const maskPublicCode = (code?: string | null) => {
  const value = String(code || "").trim();
  if (!value) return null;
  if (value.length <= 12) return `${value.slice(0, 3)}...${value.slice(-2)}`;
  return `${value.slice(0, 6)}...${value.slice(-6)}`;
};

export const formatPrintValidationEvidenceMarkdown = (report: Awaited<ReturnType<typeof generatePrintValidationEvidenceReport>>) =>
  [
    `# MSCQR Zebra Print Validation Evidence`,
    ``,
    `- Batch: ${report.batch.displayCode || report.batch.id}`,
    `- Print job: ${report.printJob.id}`,
    `- Printer: ${report.printer.profileName || report.printer.name || "Unknown"}${report.printer.model ? ` (${report.printer.model})` : ""}`,
    `- Transport: ${report.printer.transport}`,
    `- Endpoint: ${report.printer.host || "unconfigured"}:${report.printer.port || "unconfigured"}`,
    `- Label count: ${report.labelCount}`,
    `- Payload hash: ${report.payloadHash || "missing"}`,
    `- Sent at: ${report.sentAt || "missing"}`,
    `- Physical print confirmed at: ${report.physicalPrintConfirmedAt || "missing"}`,
    `- Sample scan verified at: ${report.sampleScanVerifiedAt || "missing"}`,
    `- Released at: ${report.releasedAt || "missing"}`,
    `- Released by/checker: ${report.releasedBy?.displayName || report.checker?.displayName || "missing"}`,
    `- Sample QR: ${report.sampleQr.maskedPublicCode || "missing"}`,
    `- Verify result: ${report.verify.result}`,
    `- Legacy risk: ${report.legacyRisk.status}`,
    ``,
    `## Audit Event IDs`,
    ...report.auditEventIds.map((id: string) => `- ${id}`),
  ].join("\n");

export const generatePrintValidationEvidenceReport = async (params: {
  batchId: string;
  capability: string;
  requestId: string;
  printJobId?: string | null;
  includePublicCode?: boolean;
}) => {
  const report = await readPrintingProjection({
    capability: params.capability,
    requestId: params.requestId,
    operation: "VALIDATION_EVIDENCE",
    subjectId: params.batchId,
    options: {
      printJobId: params.printJobId || null,
      includePublicCode: Boolean(params.includePublicCode),
    },
  });
  if (!report?.batch?.id) {
    throw Object.assign(new Error("Validation evidence not found."), { statusCode: 404 });
  }
  if (params.includePublicCode && report.sampleQr?.publicCode) {
    report.sampleQr.verifyUrl = buildVerifyUrl(report.sampleQr.publicCode);
  }
  return report;
};
