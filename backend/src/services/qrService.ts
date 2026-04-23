import { QRStatus, Prisma } from "@prisma/client";
import prisma from "../config/database";
import { randomNonce } from "./qrTokenService";
import { reverseGeocode } from "./locationService";
import { summarizeQrStatusCounts } from "./qrStatusMetrics";
import { guardPublicIntegrityFallback } from "../utils/publicIntegrityGuard";
import { normalizeClientIp } from "../utils/ipAddress";

const parseScanRefreshGraceMs = () => {
  const raw = Number(String(process.env.SCAN_REFRESH_GRACE_SECONDS || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return 90_000;
  return Math.max(10, Math.floor(raw)) * 1000;
};

const SCAN_REFRESH_GRACE_MS = parseScanRefreshGraceMs();

const normalizeActorToken = (value: string | null | undefined) => String(value || "").trim();
const normalizeScanIp = (value: string | null | undefined) => normalizeClientIp(value);

const isRecentRefreshDuplicate = (params: {
  latestLog:
    | {
        scannedAt: Date;
        customerUserId: string | null;
        ownershipId: string | null;
        isTrustedOwnerContext: boolean;
        ipAddress: string | null;
        userAgent: string | null;
        device: string | null;
      }
    | null;
  meta?: {
    ipAddress?: string | null;
    userAgent?: string | null;
    device?: string | null;
    customerUserId?: string | null;
    ownershipId?: string | null;
    isTrustedOwnerContext?: boolean;
  };
}) => {
  if (!params.latestLog) return false;

  const latestScannedAt = new Date(params.latestLog.scannedAt).getTime();
  if (!Number.isFinite(latestScannedAt)) return false;
  if (Date.now() - latestScannedAt > SCAN_REFRESH_GRACE_MS) return false;

  const nextTrusted = params.meta?.isTrustedOwnerContext === true;
  if (Boolean(params.latestLog.isTrustedOwnerContext) !== nextTrusted) return false;

  const currentCustomerUserId = normalizeActorToken(params.meta?.customerUserId);
  const latestCustomerUserId = normalizeActorToken(params.latestLog.customerUserId);
  if ((currentCustomerUserId || latestCustomerUserId) && currentCustomerUserId !== latestCustomerUserId) {
    return false;
  }

  const currentOwnershipId = normalizeActorToken(params.meta?.ownershipId);
  const latestOwnershipId = normalizeActorToken(params.latestLog.ownershipId);
  if ((currentOwnershipId || latestOwnershipId) && currentOwnershipId !== latestOwnershipId) {
    return false;
  }

  const currentDevice = normalizeActorToken(params.meta?.device);
  const latestDevice = normalizeActorToken(params.latestLog.device);
  if (currentDevice && latestDevice && currentDevice === latestDevice) {
    return true;
  }

  const currentUserAgent = normalizeActorToken(params.meta?.userAgent);
  const latestUserAgent = normalizeActorToken(params.latestLog.userAgent);
  const currentIpAddress = normalizeScanIp(params.meta?.ipAddress);
  const latestIpAddress = normalizeScanIp(params.latestLog.ipAddress);

  return Boolean(currentUserAgent && latestUserAgent && currentIpAddress && latestIpAddress) &&
    currentUserAgent === latestUserAgent &&
    currentIpAddress === latestIpAddress;
};

export const generateQRCode = (prefix: string, number: number): string => {
  return `${prefix}${number.toString().padStart(10, "0")}`;
};

export const parseQRCode = (code: string): { prefix: string; number: number } | null => {
  const match = code.match(/^([A-Z0-9]+)(\d{10})$/);
  if (!match) return null;

  return { prefix: match[1], number: parseInt(match[2], 10) };
};

export const makeProductCode = (input: string): string => {
  const s = String(input || "").trim().toUpperCase();
  const cleaned = s
    .replace(/[^A-Z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");

  return (cleaned || "PRODUCT").slice(0, 24);
};

export const buildVerifyUrl = (code: string): string => {
  const base =
    String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
    String(process.env.CORS_ORIGIN || "").trim() ||
    "http://localhost:8080";
  const normalized = base.replace(/\/+$/, "");
  return `${normalized}/verify/${encodeURIComponent(code)}`;
};

export const generateQRCodesForRange = async (
  licenseeId: string,
  prefix: string,
  startNumber: number,
  endNumber: number
): Promise<number> => {
  const codes: Prisma.QRCodeCreateManyInput[] = [];

  for (let i = startNumber; i <= endNumber; i++) {
    codes.push({
      code: generateQRCode(prefix, i),
      licenseeId,
      status: QRStatus.DORMANT,
      tokenNonce: randomNonce(),
    });
  }

  const batchSize = 1000;
  let created = 0;

  for (let i = 0; i < codes.length; i += batchSize) {
    const chunk = codes.slice(i, i + batchSize);
    const result = await prisma.qRCode.createMany({ data: chunk, skipDuplicates: true });
    created += result.count;
  }

  return created;
};

export const activateQRCodes = async (licenseeId: string, codes: string[]): Promise<number> => {
  const result = await prisma.qRCode.updateMany({
    where: {
      code: { in: codes },
      licenseeId,
      status: QRStatus.DORMANT,
    },
    data: { status: QRStatus.ACTIVE },
  });
  return result.count;
};

export const allocateQRCodesToBatch = async (
  batchId: string,
  licenseeId: string,
  startCode: string,
  endCode: string
): Promise<number> => {
  const result = await prisma.qRCode.updateMany({
    where: {
      licenseeId,
      code: { gte: startCode, lte: endCode },
      status: { in: [QRStatus.DORMANT, QRStatus.ACTIVE] },
      batchId: null,
    },
    data: { status: QRStatus.ALLOCATED, batchId },
  });

  return result.count;
};

export const markBatchAsPrinted = async (batchId: string, manufacturerId: string): Promise<number> => {
  const batch = await prisma.batch.findFirst({ where: { id: batchId, manufacturerId } });
  if (!batch) throw new Error("Batch not found or not assigned to this manufacturer");
  if (batch.printedAt) throw new Error("Batch has already been marked as printed");

  const now = new Date();
  await prisma.batch.update({ where: { id: batchId }, data: { printedAt: now } });

  const result = await prisma.qRCode.updateMany({
    where: { batchId, status: QRStatus.ALLOCATED },
    data: { status: QRStatus.PRINTED, printedAt: now, printedByUserId: manufacturerId },
  });

  return result.count;
};

// product batches removed

export const recordScan = async (
  code: string,
  meta?: {
    ipAddress?: string | null;
    userAgent?: string | null;
    device?: string | null;
    latitude?: number | null;
    longitude?: number | null;
    accuracy?: number | null;
    customerUserId?: string | null;
    ownershipId?: string | null;
    ownershipMatchMethod?: string | null;
    isTrustedOwnerContext?: boolean;
  },
  options?: {
    strictStorage?: boolean;
  }
) => {
  const existing = await prisma.qRCode.findUnique({
    where: { code },
    include: {
      licensee: true,
      batch: { include: { manufacturer: { select: { id: true, name: true, email: true } } } },
    },
  });

  if (!existing) throw new Error("QR code not found");

  if (
    existing.status !== QRStatus.PRINTED &&
    existing.status !== QRStatus.REDEEMED &&
    existing.status !== QRStatus.SCANNED
  ) {
    throw new Error("QR code has not been printed yet");
  }

  const isFirstScan = existing.status === QRStatus.PRINTED;

  const isQrScanActorForeignKeyError = (error: unknown) => {
    if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
    if (error.code !== "P2003") return false;

    const metaInfo = (error.meta || {}) as Record<string, unknown>;
    const haystack = `${String(metaInfo.field_name || "")} ${String(error.message || "")}`.toLowerCase();
    return haystack.includes("qrscanlog") && (haystack.includes("customeruserid") || haystack.includes("ownershipid"));
  };

  const updated = await prisma.$transaction(async (tx) => {
    const normalizedIpAddress = normalizeScanIp(meta?.ipAddress || null);
    const latestLog = await tx.qrScanLog.findFirst({
      where: { qrCodeId: existing.id },
      orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
      select: {
        scannedAt: true,
        isFirstScan: true,
        customerUserId: true,
        ownershipId: true,
        isTrustedOwnerContext: true,
        ipAddress: true,
        userAgent: true,
        device: true,
      },
    });

    if (
      isRecentRefreshDuplicate({
        latestLog,
        meta: {
          ...meta,
          ipAddress: normalizedIpAddress || null,
        },
      })
    ) {
      return {
        qr: existing,
        scanRecorded: false,
        effectiveFirstScan: Boolean(latestLog?.isFirstScan),
      };
    }

    const location = await reverseGeocode(meta?.latitude ?? null, meta?.longitude ?? null);
    const qr = await tx.qRCode.update({
      where: { code },
      data: {
        status: isFirstScan ? QRStatus.REDEEMED : existing.status,
        scannedAt: isFirstScan ? new Date() : existing.scannedAt,
        redeemedAt: isFirstScan ? new Date() : existing.redeemedAt,
        lastScanIp: normalizedIpAddress || null,
        lastScanUserAgent: meta?.userAgent ?? null,
        lastScanDevice: meta?.device ?? null,
        scanCount: { increment: 1 },
      },
      include: {
        licensee: true,
        batch: { include: { manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } } } },
      },
    });

    const baseScanLogData = {
      code: qr.code,
      qrCodeId: qr.id,
      licenseeId: qr.licenseeId,
      batchId: qr.batchId ?? null,
      status: qr.status,
      isFirstScan,
      scanCount: qr.scanCount ?? 0,
      customerUserId: meta?.customerUserId ?? null,
      ownershipId: meta?.ownershipId ?? null,
      ownershipMatchMethod: meta?.ownershipMatchMethod ?? null,
      isTrustedOwnerContext: meta?.isTrustedOwnerContext === true,
      ipAddress: normalizedIpAddress || null,
      userAgent: meta?.userAgent ?? null,
      device: meta?.device ?? null,
      latitude: meta?.latitude ?? null,
      longitude: meta?.longitude ?? null,
      accuracy: meta?.accuracy ?? null,
      locationName: location?.name || null,
      locationCountry: location?.country || null,
      locationRegion: location?.region || null,
      locationCity: location?.city || null,
    };

    try {
      await tx.qrScanLog.create({
        data: baseScanLogData,
      });
    } catch (error) {
      if (isQrScanActorForeignKeyError(error)) {
        guardPublicIntegrityFallback({
          strictStorage: options?.strictStorage,
          warningKey: "verify-qr-log-actor-fk",
          warningMessage:
            "[verify] QrScanLog customer/ownership foreign key is stale. Retrying verification log without actor linkage.",
          degradedMessage: "Verification is temporarily unavailable because scan-log integrity checks are stale.",
          degradedCode: "PUBLIC_SCAN_LOG_INTEGRITY_STALE",
        });
        await tx.qrScanLog.create({
          data: {
            ...baseScanLogData,
            customerUserId: null,
            ownershipId: null,
            ownershipMatchMethod: null,
            isTrustedOwnerContext: false,
          },
        });
      } else {
        throw error;
      }
    }

    return {
      qr,
      scanRecorded: true,
      effectiveFirstScan: isFirstScan,
    };
  });

  return {
    qrCode: updated.qr,
    isFirstScan: updated.effectiveFirstScan,
    scanRecorded: updated.scanRecorded,
  };
};

export const getQRStats = async (licenseeId?: string) => {
  const where = licenseeId ? { licenseeId } : {};
  const rollups = await prisma.inventoryStatusRollup.aggregate({
    where,
    _sum: {
      totalCodes: true,
      dormant: true,
      active: true,
      activated: true,
      allocated: true,
      printed: true,
      redeemed: true,
      blocked: true,
      scanned: true,
    },
  });

  const hasRollupData = Object.values(rollups._sum || {}).some((value) => Number(value || 0) > 0);

  let total = 0;
  let byStatus: Record<string, number> = {};

  if (hasRollupData) {
    const unbatchedStats = await prisma.qRCode.groupBy({
      by: ["status"],
      where: {
        ...where,
        batchId: null,
      },
      _count: true,
    });

    const unbatchedTotal = await prisma.qRCode.count({
      where: {
        ...where,
        batchId: null,
      },
    });

    byStatus = {
      DORMANT: Number(rollups._sum?.dormant || 0),
      ACTIVE: Number(rollups._sum?.active || 0),
      ACTIVATED: Number(rollups._sum?.activated || 0),
      ALLOCATED: Number(rollups._sum?.allocated || 0),
      PRINTED: Number(rollups._sum?.printed || 0),
      REDEEMED: Number(rollups._sum?.redeemed || 0),
      BLOCKED: Number(rollups._sum?.blocked || 0),
      SCANNED: Number(rollups._sum?.scanned || 0),
    };

    for (const stat of unbatchedStats) {
      byStatus[stat.status] = Number(byStatus[stat.status] || 0) + Number(stat._count || 0);
    }

    total = Number(rollups._sum?.totalCodes || 0) + unbatchedTotal;
  } else {
    const stats = await prisma.qRCode.groupBy({
      by: ["status"],
      where,
      _count: true,
    });

    total = await prisma.qRCode.count({ where });
    byStatus = stats.reduce((acc, s) => {
      acc[s.status] = s._count;
      return acc;
    }, {} as Record<string, number>);
  }

  return {
    total,
    byStatus,
    ...summarizeQrStatusCounts(byStatus),
  };
};
