import { QRStatus, Prisma } from "@prisma/client";
import prisma from "../config/database";
import { randomNonce } from "./qrTokenService";
import { reverseGeocode } from "./locationService";
import { warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";

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
  const location = await reverseGeocode(meta?.latitude ?? null, meta?.longitude ?? null);

  const isQrScanActorForeignKeyError = (error: unknown) => {
    if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
    if (error.code !== "P2003") return false;

    const metaInfo = (error.meta || {}) as Record<string, unknown>;
    const haystack = `${String(metaInfo.field_name || "")} ${String(error.message || "")}`.toLowerCase();
    return haystack.includes("qrscanlog") && (haystack.includes("customeruserid") || haystack.includes("ownershipid"));
  };

  const updated = await prisma.$transaction(async (tx) => {
    const qr = await tx.qRCode.update({
      where: { code },
      data: {
        status: isFirstScan ? QRStatus.REDEEMED : existing.status,
        scannedAt: isFirstScan ? new Date() : existing.scannedAt,
        redeemedAt: isFirstScan ? new Date() : existing.redeemedAt,
        lastScanIp: meta?.ipAddress ?? null,
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
      ipAddress: meta?.ipAddress ?? null,
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
        warnStorageUnavailableOnce(
          "verify-qr-log-actor-fk",
          "[verify] QrScanLog customer/ownership foreign key is stale. Retrying verification log without actor linkage."
        );
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

    return qr;
  });

  return { qrCode: updated, isFirstScan };
};

export const getQRStats = async (licenseeId?: string) => {
  const where = licenseeId ? { licenseeId } : {};

  const stats = await prisma.qRCode.groupBy({
    by: ["status"],
    where,
    _count: true,
  });

  const total = await prisma.qRCode.count({ where });

  return {
    total,
    byStatus: stats.reduce((acc, s) => {
      acc[s.status] = s._count;
      return acc;
    }, {} as Record<string, number>),
  };
};
