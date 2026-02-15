import { QRStatus, type Prisma } from "@prisma/client";

import prisma from "../config/database";
import { reverseGeocode } from "./locationService";
import { classifyScan } from "./scanRiskService";

type RecordClassifiedScanInput = {
  qrId: string;
  currentStatus: QRStatus;
  allowRedeem: boolean;
  existingScannedAt?: Date | null;
  existingRedeemedAt?: Date | null;
  ipAddress?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
  device?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
  customerUserId?: string | null;
  anonVisitorId?: string | null;
  visitorFingerprint?: string | null;
  scannedAt?: Date;
};

export type RecordClassifiedScanResult = {
  qrCode: Prisma.QRCodeGetPayload<{
    include: {
      licensee: {
        select: {
          id: true;
          name: true;
          prefix: true;
          brandName: true;
          location: true;
          website: true;
          supportEmail: true;
          supportPhone: true;
        };
      };
      batch: {
        select: {
          id: true;
          name: true;
          printedAt: true;
          manufacturer: {
            select: {
              id: true;
              name: true;
              email: true;
              location: true;
              website: true;
            };
          };
        };
      };
    };
  }>;
  classification: ReturnType<typeof classifyScan>;
  ownership: { customerUserId: string; claimedAt: Date } | null;
  location: {
    name: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
  } | null;
};

const toCoarseCoord = (value?: number | null) => {
  if (value == null || !Number.isFinite(value)) return null;
  return Number(value.toFixed(2));
};

export const recordClassifiedScan = async (input: RecordClassifiedScanInput): Promise<RecordClassifiedScanResult> => {
  const now = input.scannedAt || new Date();
  const latitude = toCoarseCoord(input.latitude);
  const longitude = toCoarseCoord(input.longitude);
  const accuracy = input.accuracy != null && Number.isFinite(input.accuracy) ? Number(input.accuracy) : null;

  const location = await reverseGeocode(latitude, longitude);

  return prisma.$transaction(async (tx) => {
    const [history, ownership] = await Promise.all([
      tx.qrScanLog.findMany({
        where: { qrCodeId: input.qrId },
        orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
        take: 60,
        select: {
          scannedAt: true,
          customerUserId: true,
          anonVisitorId: true,
          locationCountry: true,
          latitude: true,
          longitude: true,
        },
      }),
      tx.productOwnership.findUnique({
        where: { qrCodeId: input.qrId },
        select: { customerUserId: true, claimedAt: true },
      }),
    ]);

    const classification = classifyScan(
      {
        scannedAt: now,
        customerUserId: input.customerUserId || null,
        anonVisitorId: input.anonVisitorId || null,
        ownerCustomerUserId: ownership?.customerUserId || null,
        latitude,
        longitude,
        locationCountry: location?.country || null,
      },
      history.map((entry) => ({
        scannedAt: entry.scannedAt,
        customerUserId: entry.customerUserId || null,
        anonVisitorId: entry.anonVisitorId || null,
        locationCountry: entry.locationCountry || null,
        latitude: entry.latitude,
        longitude: entry.longitude,
      }))
    );

    const updatedQr = await tx.qRCode.update({
      where: { id: input.qrId },
      data: {
        scanCount: { increment: 1 },
        scannedAt: input.existingScannedAt || now,
        status: input.allowRedeem ? QRStatus.REDEEMED : input.currentStatus,
        redeemedAt: input.allowRedeem ? now : input.existingRedeemedAt || null,
        redeemedDeviceFingerprint: input.allowRedeem
          ? input.visitorFingerprint || input.device || null
          : undefined,
        lastScanIp: input.ipAddress || null,
        lastScanUserAgent: input.userAgent || null,
        lastScanDevice: input.visitorFingerprint || input.device || null,
      },
      include: {
        licensee: {
          select: {
            id: true,
            name: true,
            prefix: true,
            brandName: true,
            location: true,
            website: true,
            supportEmail: true,
            supportPhone: true,
          },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
            manufacturer: {
              select: {
                id: true,
                name: true,
                email: true,
                location: true,
                website: true,
              },
            },
          },
        },
      },
    });

    await tx.qrScanLog.create({
      data: {
        code: updatedQr.code,
        qrCodeId: updatedQr.id,
        licenseeId: updatedQr.licenseeId,
        batchId: updatedQr.batchId ?? null,
        status: updatedQr.status,
        isFirstScan: input.allowRedeem,
        scanCount: updatedQr.scanCount ?? 0,
        ipAddress: input.ipAddress || null,
        ipHash: input.ipHash || null,
        userAgent: input.userAgent || null,
        device: input.device || null,
        latitude,
        longitude,
        accuracy,
        locationName: location?.name || null,
        locationCountry: location?.country || null,
        locationRegion: location?.region || null,
        locationCity: location?.city || null,
        customerUserId: input.customerUserId || null,
        anonVisitorId: input.anonVisitorId || null,
        visitorFingerprint: input.visitorFingerprint || null,
        riskClassification: classification.classification,
        riskReasons: classification.reasons,
      },
    });

    return {
      qrCode: updatedQr,
      classification,
      ownership,
      location,
    };
  });
};
