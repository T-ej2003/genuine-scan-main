import { BatchLifecycleState, QRStatus, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { buildVerifyUrl } from "./qrService";
import { isLegacyPublicCode } from "./legacyQrRotationService";
import { isLicenseeAdminRole, isManufacturerRole, isPlatformRole } from "./manufacturerScopeService";

type EvidenceActor = {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  linkedLicenseeIds?: string[] | null;
};

type EvidenceBatchScope = {
  licenseeId: string;
  manufacturerId?: string | null;
};

const manufacturerAdminViewRoles = new Set<UserRole>([UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN]);

export const canViewPrintValidationEvidence = (actor: EvidenceActor, batch: EvidenceBatchScope) => {
  if (isPlatformRole(actor.role)) return true;
  if (isLicenseeAdminRole(actor.role)) return Boolean(actor.licenseeId && actor.licenseeId === batch.licenseeId);
  if (!isManufacturerRole(actor.role) || !manufacturerAdminViewRoles.has(actor.role)) return false;
  if (actor.userId === batch.manufacturerId) return true;
  if (actor.licenseeId && actor.licenseeId === batch.licenseeId) return true;
  return Array.isArray(actor.linkedLicenseeIds) && actor.linkedLicenseeIds.includes(batch.licenseeId);
};

export const maskPublicCode = (code?: string | null) => {
  const value = String(code || "").trim();
  if (!value) return null;
  if (value.length <= 12) return `${value.slice(0, 3)}...${value.slice(-2)}`;
  return `${value.slice(0, 6)}...${value.slice(-6)}`;
};

const iso = (value?: Date | string | null) => (value ? new Date(value).toISOString() : null);

const resolveVerifyResult = (qr: { status: QRStatus; batch?: { lifecycleState?: BatchLifecycleState | null } | null } | null) => {
  if (!qr) return "not_found";
  if (qr.status === QRStatus.BLOCKED) return "blocked";
  if (qr.batch?.lifecycleState === BatchLifecycleState.RELEASED) return "authentic_released";
  if (qr.status === QRStatus.PRINTED || qr.status === QRStatus.ACTIVATED) return "authentic_not_released";
  return "not_ready";
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
    ...report.auditEventIds.map((id) => `- ${id}`),
  ].join("\n");

export const generatePrintValidationEvidenceReport = async (params: {
  batchId: string;
  actor: EvidenceActor;
  printJobId?: string | null;
  includePublicCode?: boolean;
}) => {
  const batch = await prisma.batch.findUnique({
    where: { id: params.batchId },
    include: {
      licensee: { select: { id: true, name: true, prefix: true } },
      manufacturer: { select: { id: true, name: true, email: true, role: true } },
    },
  });
  if (!batch) throw Object.assign(new Error("Validation evidence not found."), { statusCode: 404 });
  if (!canViewPrintValidationEvidence(params.actor, batch)) {
    throw Object.assign(new Error("Validation evidence not found."), { statusCode: 404 });
  }

  const printJob = await prisma.printJob.findFirst({
    where: { batchId: batch.id, ...(params.printJobId ? { id: params.printJobId } : {}) },
    include: {
      printer: {
        include: { profile: true },
      },
      approvedByUser: { select: { id: true, name: true, email: true, role: true } },
    },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
  });
  if (!printJob) throw Object.assign(new Error("Validation evidence not found."), { statusCode: 404 });

  const [sampleEvent, releaseEvent, approvalEvent, auditEvents, legacyCount, unsafeLegacyCount] = await Promise.all([
    prisma.printAuditEvent.findFirst({
      where: { batchId: batch.id, printJobId: printJob.id, eventType: "sample_scan_verified" },
      orderBy: { createdAt: "desc" },
    }),
    prisma.printAuditEvent.findFirst({
      where: { batchId: batch.id, printJobId: printJob.id, eventType: "batch_released" },
      orderBy: { createdAt: "desc" },
    }),
    prisma.printAuditEvent.findFirst({
      where: { batchId: batch.id, printJobId: printJob.id, eventType: "batch_release_approval_granted" },
      orderBy: { createdAt: "desc" },
    }),
    prisma.printAuditEvent.findMany({
      where: {
        batchId: batch.id,
        OR: [{ printJobId: printJob.id }, { eventType: { startsWith: "batch_release" } }],
      },
      orderBy: { createdAt: "asc" },
      select: { id: true },
    }),
    prisma.qRCode.count({ where: { batchId: batch.id, code: { not: { startsWith: "c_" } } } }),
    prisma.qRCode.count({
      where: {
        batchId: batch.id,
        code: { not: { startsWith: "c_" } },
        OR: [
          { printedAt: { not: null } },
          { scannedAt: { not: null } },
          { scanCount: { gt: 0 } },
          { status: { in: [QRStatus.PRINTED, QRStatus.SCANNED, QRStatus.REDEEMED, QRStatus.BLOCKED] } },
        ],
      },
    }),
  ]);

  const sampleQr = await prisma.qRCode.findFirst({
    where: {
      batchId: batch.id,
      printJobId: printJob.id,
      ...(sampleEvent?.qrCodeId ? { id: sampleEvent.qrCodeId } : {}),
    },
    include: { batch: { select: { lifecycleState: true } } },
    orderBy: [{ printedAt: "asc" }, { createdAt: "asc" }],
  });

  const releasedBy = batch.releasedByUserId
    ? await prisma.user.findUnique({
        where: { id: batch.releasedByUserId },
        select: { id: true, name: true, email: true, role: true },
      })
    : null;
  const checker = printJob.approvedByUser || releasedBy || null;
  const sampleCode = sampleQr?.code || null;

  return {
    generatedAt: new Date().toISOString(),
    batch: {
      id: batch.id,
      displayCode: batch.name || batch.startCode || null,
      lifecycleState: batch.lifecycleState,
      brand: {
        id: batch.licensee.id,
        name: batch.licensee.name,
        prefix: batch.licensee.prefix,
      },
    },
    printJob: {
      id: printJob.id,
      status: printJob.status,
      pipelineState: printJob.pipelineState,
    },
    printer: {
      id: printJob.printer?.id || null,
      name: printJob.printer?.name || null,
      profileName: printJob.printer?.profile?.modelName || printJob.printer?.profile?.modelFamily || null,
      model: printJob.printer?.model || printJob.printer?.profile?.modelName || null,
      transport: "tcp-raw",
      host: printJob.printer?.host || printJob.printer?.ipAddress || null,
      port: printJob.printer?.port || null,
    },
    labelCount: printJob.itemCount || printJob.quantity || batch.totalCodes,
    payloadHash: printJob.payloadHash || null,
    sentAt: iso(printJob.sentAt),
    physicalPrintConfirmedAt: iso(printJob.confirmedAt),
    sampleScanVerifiedAt: iso(sampleEvent?.createdAt),
    releasedAt: iso(batch.releasedAt),
    releasedBy: releasedBy
      ? { id: releasedBy.id, displayName: releasedBy.name || releasedBy.email, role: releasedBy.role }
      : null,
    checker: checker
      ? { id: checker.id, displayName: checker.name || checker.email, role: checker.role }
      : null,
    sampleQr: {
      id: sampleQr?.id || null,
      publicCode: params.includePublicCode ? sampleCode : undefined,
      maskedPublicCode: maskPublicCode(sampleCode),
      verifyUrl: params.includePublicCode && sampleCode ? buildVerifyUrl(sampleCode) : null,
    },
    verify: {
      result: resolveVerifyResult(sampleQr),
      routeUsesExactPublicCode: Boolean(sampleCode && !isLegacyPublicCode(sampleCode)),
    },
    auditEventIds: auditEvents.map((event) => event.id),
    auditEvents: {
      sampleScanVerifiedId: sampleEvent?.id || null,
      batchReleasedId: releaseEvent?.id || null,
      approvalGrantedId: approvalEvent?.id || null,
    },
    legacyRisk: {
      status: legacyCount === 0 ? "no_legacy_public_codes_in_batch" : unsafeLegacyCount > 0 ? "legacy_codes_locked" : "legacy_codes_review_required",
      totalLegacyCodes: legacyCount,
      unsafeLegacyCodes: unsafeLegacyCount,
    },
  };
};
