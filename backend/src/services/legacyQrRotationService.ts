import { BatchLifecycleState, Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { generatePublicQRCode } from "./qrService";

const ROTATION_SAFE_STATUSES = new Set<QRStatus>([QRStatus.DORMANT, QRStatus.ACTIVE, QRStatus.ALLOCATED]);
const EXTERNAL_AUDIT_ACTION_PATTERN = /(PRINT|SCAN|VERIFY|SIGNED|EXPORT|DOWNLOAD|REDEEM|OWNERSHIP|TRANSFER|CUSTOMER|PUBLIC|PACK)/i;

type PrismaLike = Pick<
  typeof prisma,
  "qRCode" | "licensee" | "batch" | "qrScanLog" | "verificationDecision" | "auditLog" | "printAuditEvent"
>;

type LegacyQrSafetyRow = {
  id: string;
  code: string;
  displayCode?: string | null;
  status: QRStatus;
  batchId?: string | null;
  printJobId?: string | null;
  scannedAt?: Date | string | null;
  scanCount?: number | null;
  printedAt?: Date | string | null;
  redeemedAt?: Date | string | null;
  tokenIssuedAt?: Date | string | null;
  customerVerifiableAt?: Date | string | null;
  signedFirstSeenAt?: Date | string | null;
  lastSignedVerificationAt?: Date | string | null;
  batch?: {
    printedAt?: Date | string | null;
    printPackDownloadedAt?: Date | string | null;
    lifecycleState?: BatchLifecycleState | string | null;
    releasedAt?: Date | string | null;
  } | null;
};

type LegacyQrEvidence = {
  scanLogs: number;
  verificationDecisions: number;
  auditEvents: number;
  printAuditEvents: number;
};

export const isLegacyPublicCode = (code?: string | null) => !String(code || "").startsWith("c_");

export const explainLegacyQrRotationBlock = (
  qr: LegacyQrSafetyRow,
  evidence: LegacyQrEvidence = {
    scanLogs: 0,
    verificationDecisions: 0,
    auditEvents: 0,
    printAuditEvents: 0,
  }
) => {
  const reasons: string[] = [];
  if (!isLegacyPublicCode(qr.code)) reasons.push("not_legacy_public_code");
  if (!ROTATION_SAFE_STATUSES.has(qr.status)) reasons.push(`unsafe_status_${qr.status}`);
  if (qr.printedAt) reasons.push("printed_at_present");
  if (qr.scannedAt) reasons.push("scanned_at_present");
  if (Number(qr.scanCount || 0) > 0) reasons.push("scan_count_present");
  if (qr.redeemedAt) reasons.push("redeemed_at_present");
  if (qr.printJobId) reasons.push("print_job_linked");
  if (qr.tokenIssuedAt) reasons.push("signed_token_issued");
  if (qr.customerVerifiableAt) reasons.push("customer_verifiable");
  if (qr.signedFirstSeenAt || qr.lastSignedVerificationAt) reasons.push("signed_verification_seen");
  if (qr.batch?.printedAt) reasons.push("batch_printed");
  if (qr.batch?.printPackDownloadedAt) reasons.push("batch_print_pack_downloaded");
  if (qr.batch?.releasedAt || qr.batch?.lifecycleState === BatchLifecycleState.RELEASED) {
    reasons.push("batch_released");
  }
  if (evidence.scanLogs > 0) reasons.push("scan_log_exists");
  if (evidence.verificationDecisions > 0) reasons.push("verification_decision_exists");
  if (evidence.auditEvents > 0) reasons.push("external_audit_evidence_exists");
  if (evidence.printAuditEvents > 0) reasons.push("print_audit_evidence_exists");
  return reasons;
};

export const canRotateLegacyQrCode = (qr: LegacyQrSafetyRow, evidence?: LegacyQrEvidence) =>
  explainLegacyQrRotationBlock(qr, evidence).length === 0;

const unsafeLegacyQrWhere = {
  OR: [
    { printedAt: { not: null } },
    { scannedAt: { not: null } },
    { scanCount: { gt: 0 } },
    { redeemedAt: { not: null } },
    { printJobId: { not: null } },
    { tokenIssuedAt: { not: null } },
    { customerVerifiableAt: { not: null } },
    { signedFirstSeenAt: { not: null } },
    { lastSignedVerificationAt: { not: null } },
    { status: { notIn: Array.from(ROTATION_SAFE_STATUSES) } },
    { batch: { is: { printedAt: { not: null } } } },
    { batch: { is: { printPackDownloadedAt: { not: null } } } },
    { batch: { is: { releasedAt: { not: null } } } },
    { batch: { is: { lifecycleState: BatchLifecycleState.RELEASED } } },
  ],
} satisfies Prisma.QRCodeWhereInput;

const legacyGroupKey = (row: { licenseeId: string; batchId: string | null; status: QRStatus }) =>
  [row.licenseeId, row.batchId || "", row.status].join("|");

type LegacyQrReportCsvPayload = {
  generatedAt?: string;
  totalLegacyCodes?: number;
  knownUnsafeLegacyCodes?: number;
  potentiallyRotatableLegacyCodes?: number;
  blockerReasonCounts?: Record<string, number>;
  groups: Array<{
    brandId: string;
    brandName: string | null;
    brandPrefix: string | null;
    batchId: string | null;
    batchName: string | null;
    batchLifecycleState: BatchLifecycleState | string | null;
    batchReleasedAt: string | null;
    status: QRStatus | string;
    count: number;
    knownUnsafeCount: number;
    potentiallyRotatableCount: number;
    batchPrintedAt: string | null;
    batchPrintPackDownloadedAt: string | null;
  }>;
};

export const serializeLegacyQrReportCsv = (report: LegacyQrReportCsvPayload) => {
  const headers = [
    "brandId",
    "brandName",
    "brandPrefix",
    "batchId",
    "batchName",
    "batchLifecycleState",
    "batchReleasedAt",
    "status",
    "legacyCount",
    "knownUnsafeCount",
    "potentiallyRotatableCount",
    "batchPrintedAt",
    "batchPrintPackDownloadedAt",
    "generatedAt",
    "totalLegacyCodes",
    "knownUnsafeLegacyCodes",
    "potentiallyRotatableLegacyCodes",
    "blockerReasonCounts",
  ];
  const escape = (value: unknown) => {
    if (value === null || value === undefined) return "";
    const text = String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return [
    headers.join(","),
    ...report.groups.map((row) =>
      [
        row.brandId,
        row.brandName,
        row.brandPrefix,
        row.batchId,
        row.batchName,
        row.batchLifecycleState,
        row.batchReleasedAt,
        row.status,
        row.count,
        row.knownUnsafeCount,
        row.potentiallyRotatableCount,
        row.batchPrintedAt,
        row.batchPrintPackDownloadedAt,
        report.generatedAt || "",
        report.totalLegacyCodes ?? "",
        report.knownUnsafeLegacyCodes ?? "",
        report.potentiallyRotatableLegacyCodes ?? "",
        report.blockerReasonCounts ? JSON.stringify(report.blockerReasonCounts) : "",
      ]
        .map(escape)
        .join(",")
    ),
  ].join("\n");
};

export const getLegacyQrReport = async (client: PrismaLike = prisma) => {
  const legacyWhere = { code: { not: { startsWith: "c_" } } } satisfies Prisma.QRCodeWhereInput;
  const blockerReasonQueries: Record<string, Prisma.QRCodeWhereInput> = {
    unsafe_status: { status: { notIn: Array.from(ROTATION_SAFE_STATUSES) } },
    printed_at_present: { printedAt: { not: null } },
    scanned_at_present: { scannedAt: { not: null } },
    scan_count_present: { scanCount: { gt: 0 } },
    redeemed_at_present: { redeemedAt: { not: null } },
    print_job_linked: { printJobId: { not: null } },
    signed_token_issued: { tokenIssuedAt: { not: null } },
    customer_verifiable: { customerVerifiableAt: { not: null } },
    signed_verification_seen: {
      OR: [{ signedFirstSeenAt: { not: null } }, { lastSignedVerificationAt: { not: null } }],
    },
    batch_printed: { batch: { is: { printedAt: { not: null } } } },
    batch_print_pack_downloaded: { batch: { is: { printPackDownloadedAt: { not: null } } } },
    batch_released: {
      OR: [
        { batch: { is: { releasedAt: { not: null } } } },
        { batch: { is: { lifecycleState: BatchLifecycleState.RELEASED } } },
      ],
    },
  };
  const blockerReasonEntries = Object.entries(blockerReasonQueries);

  const [groups, unsafeGroups, ...blockerCounts] = await Promise.all([
    client.qRCode.groupBy({
      by: ["licenseeId", "batchId", "status"],
      where: legacyWhere,
      _count: {
        id: true,
      },
      orderBy: [{ licenseeId: "asc" }, { batchId: "asc" }, { status: "asc" }],
    }),
    client.qRCode.groupBy({
      by: ["licenseeId", "batchId", "status"],
      where: {
        AND: [legacyWhere, unsafeLegacyQrWhere],
      },
      _count: {
        id: true,
      },
    }),
    ...blockerReasonEntries.map(([, where]) =>
      client.qRCode.count({
        where: {
          AND: [legacyWhere, where],
        },
      })
    ),
  ]);

  const licenseeIds = Array.from(new Set(groups.map((group) => group.licenseeId).filter(Boolean)));
  const batchIds = Array.from(new Set(groups.map((group) => group.batchId).filter(Boolean))) as string[];

  const [licensees, batches] = await Promise.all([
    client.licensee.findMany({
      where: { id: { in: licenseeIds } },
      select: { id: true, name: true, prefix: true },
    }),
    batchIds.length > 0
      ? client.batch.findMany({
          where: { id: { in: batchIds } },
          select: {
            id: true,
            name: true,
            startCode: true,
            endCode: true,
            printedAt: true,
            printPackDownloadedAt: true,
            lifecycleState: true,
            releasedAt: true,
          },
        })
      : Promise.resolve([]),
  ]);

  const licenseeById = new Map(licensees.map((licensee) => [licensee.id, licensee]));
  const batchById = new Map(batches.map((batch) => [batch.id, batch]));
  const unsafeCountByGroup = new Map(unsafeGroups.map((group) => [legacyGroupKey(group), group._count.id]));
  const rows = groups.map((group) => {
    const licensee = licenseeById.get(group.licenseeId) || null;
    const batch = group.batchId ? batchById.get(group.batchId) || null : null;
    const knownUnsafeCount = unsafeCountByGroup.get(legacyGroupKey(group)) || 0;
    return {
      brandId: group.licenseeId,
      brandName: licensee?.name || null,
      brandPrefix: licensee?.prefix || null,
      batchId: group.batchId || null,
      batchName: batch?.name || null,
      batchStartCode: batch?.startCode || null,
      batchEndCode: batch?.endCode || null,
      batchPrintedAt: batch?.printedAt?.toISOString?.() || null,
      batchPrintPackDownloadedAt: batch?.printPackDownloadedAt?.toISOString?.() || null,
      batchLifecycleState: batch?.lifecycleState || null,
      batchReleasedAt: batch?.releasedAt?.toISOString?.() || null,
      status: group.status,
      count: group._count.id,
      knownUnsafeCount,
      potentiallyRotatableCount: Math.max(0, group._count.id - knownUnsafeCount),
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    totalLegacyCodes: rows.reduce((sum, row) => sum + row.count, 0),
    knownUnsafeLegacyCodes: rows.reduce((sum, row) => sum + row.knownUnsafeCount, 0),
    potentiallyRotatableLegacyCodes: rows.reduce((sum, row) => sum + row.potentiallyRotatableCount, 0),
    blockerReasonCounts: Object.fromEntries(
      blockerReasonEntries.map(([reason], index) => [reason, Number(blockerCounts[index] || 0)])
    ),
    note: "Potentially rotatable counts exclude obvious DB blockers; rotation still performs per-code audit evidence checks before changing any public code.",
    groups: rows,
  };
};

const countExternalAuditEvidence = async (
  client: Prisma.TransactionClient,
  qr: Pick<LegacyQrSafetyRow, "id" | "code">
): Promise<LegacyQrEvidence> => {
  const [scanLogs, verificationDecisions, auditRows, printAuditEvents] = await Promise.all([
    client.qrScanLog.count({ where: { qrCodeId: qr.id } }),
    client.verificationDecision.count({
      where: {
        OR: [{ qrCodeId: qr.id }, { code: qr.code }],
      },
    }),
    client.auditLog.findMany({
      where: {
        OR: [
          { entityType: "QRCode", entityId: qr.id },
          { entityType: "QRCode", entityId: qr.code },
          { entityType: "QR_CODE", entityId: qr.id },
          { entityType: "QR_CODE", entityId: qr.code },
        ],
      },
      select: { action: true },
      take: 20,
    }),
    client.printAuditEvent.count({
      where: {
        OR: [{ qrCodeId: qr.id }, { metadata: { path: ["publicCode"], equals: qr.code } }],
      },
    }),
  ]);

  return {
    scanLogs,
    verificationDecisions,
    auditEvents: auditRows.filter((row) => EXTERNAL_AUDIT_ACTION_PATTERN.test(row.action)).length,
    printAuditEvents,
  };
};

const generateUniquePublicCode = async (client: Prisma.TransactionClient) => {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const code = generatePublicQRCode();
    const existing = await client.qRCode.findUnique({ where: { code }, select: { id: true } });
    if (!existing) return code;
  }
  throw new Error("Could not allocate a unique public QR code.");
};

export const rotateEligibleLegacyQrCodes = async (params: {
  actorId: string;
  ids?: string[];
  limit?: number;
  dryRun?: boolean;
}) => {
  const ids = Array.from(new Set((params.ids || []).map((id) => String(id || "").trim()).filter(Boolean)));
  const limit = Math.max(1, Math.min(Number(params.limit || 250) || 250, 500));

  return prisma.$transaction(
    async (tx) => {
      const candidates = await tx.qRCode.findMany({
        where: {
          code: { not: { startsWith: "c_" } },
          ...(ids.length > 0 ? { id: { in: ids } } : {}),
        },
        include: {
          batch: {
            select: {
              printedAt: true,
              printPackDownloadedAt: true,
              lifecycleState: true,
              releasedAt: true,
            },
          },
        },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        take: limit,
      });

      const rotated: Array<{ id: string; previousPublicCode: string; newPublicCode?: string; displayCode: string | null }> = [];
      const skipped: Array<{ id: string; publicCode: string; reasons: string[] }> = [];

      for (const qr of candidates) {
        const evidence = await countExternalAuditEvidence(tx, qr);
        const reasons = explainLegacyQrRotationBlock(qr, evidence);
        if (reasons.length > 0) {
          skipped.push({ id: qr.id, publicCode: qr.code, reasons });
          continue;
        }

        if (params.dryRun) {
          rotated.push({ id: qr.id, previousPublicCode: qr.code, displayCode: qr.displayCode || qr.code });
          continue;
        }

        const newCode = await generateUniquePublicCode(tx);
        const displayCode = qr.displayCode || qr.code;
        const updated = await tx.qRCode.updateMany({
          where: {
            id: qr.id,
            code: qr.code,
            printedAt: null,
            scannedAt: null,
            redeemedAt: null,
            printJobId: null,
            tokenIssuedAt: null,
            customerVerifiableAt: null,
            signedFirstSeenAt: null,
            lastSignedVerificationAt: null,
            status: { in: Array.from(ROTATION_SAFE_STATUSES) },
            batch: {
              is: {
                printedAt: null,
                printPackDownloadedAt: null,
                releasedAt: null,
                lifecycleState: { not: BatchLifecycleState.RELEASED },
              },
            },
          },
          data: {
            code: newCode,
            displayCode,
            issuanceMode: "ROTATED_SECURE_PUBLIC_CODE",
            tokenNonce: null,
            tokenExpiresAt: null,
            tokenHash: null,
          },
        });

        if (updated.count !== 1) {
          skipped.push({ id: qr.id, publicCode: qr.code, reasons: ["candidate_changed_during_rotation"] });
          continue;
        }

        await tx.auditLog.create({
          data: {
            userId: params.actorId,
            licenseeId: qr.licenseeId,
            action: "QR_PUBLIC_CODE_ROTATED",
            entityType: "QRCode",
            entityId: qr.id,
            details: {
              previousPublicCode: qr.code,
              newPublicCode: newCode,
              displayCode,
              reason: "legacy_predictable_code_rotation",
            } as Prisma.InputJsonValue,
          },
        });
        rotated.push({ id: qr.id, previousPublicCode: qr.code, newPublicCode: newCode, displayCode });
      }

      return {
        dryRun: Boolean(params.dryRun),
        scanned: candidates.length,
        rotated,
        skipped,
      };
    },
    { timeout: 20_000 }
  );
};
