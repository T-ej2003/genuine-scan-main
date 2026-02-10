import { Prisma, QRStatus } from "@prisma/client";
import prisma from "../config/database";
import { generateQRCode, parseQRCode } from "./qrService";
import { randomNonce } from "./qrTokenService";

type DbClient = Prisma.TransactionClient;

export const lockLicenseeAllocation = async (tx: DbClient, licenseeId: string) => {
  // Transaction-scoped advisory lock prevents concurrent next-range collisions per licensee.
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`qr_alloc_${licenseeId}`}))`;
};

export const getNextLicenseeQrNumber = async (tx: DbClient, licenseeId: string) => {
  const last = await tx.qRCode.findFirst({
    where: { licenseeId },
    orderBy: { code: "desc" },
    select: { code: true },
  });
  if (!last?.code) return 1;

  const parsed = parseQRCode(last.code);
  return (parsed?.number ?? 0) + 1;
};

export type AllocateQrRangeParams = {
  licenseeId: string;
  startNumber: number;
  endNumber: number;
  createdByUserId?: string | null;
  source?: string | null;
  requestId?: string | null;
  createReceivedBatch?: boolean;
  tx?: DbClient;
};

export const allocateQrRange = async (params: AllocateQrRangeParams) => {
  const {
    licenseeId,
    startNumber,
    endNumber,
    createdByUserId,
    source,
    requestId,
    createReceivedBatch,
    tx,
  } = params;

  const db = tx ?? prisma;

  const licensee = await db.licensee.findUnique({
    where: { id: licenseeId },
    select: { id: true, prefix: true },
  });
  if (!licensee) throw new Error("Licensee not found");

  const startCode = generateQRCode(licensee.prefix, startNumber);
  const endCode = generateQRCode(licensee.prefix, endNumber);
  const totalCodes = endNumber - startNumber + 1;

  // ensure no overlap with existing codes
  const existing = await db.qRCode.count({
    where: { licenseeId, code: { gte: startCode, lte: endCode } },
  });
  if (existing > 0) {
    throw new Error(`Range overlaps existing QR codes (${existing} found in the range).`);
  }

  const range = await db.qRRange.create({
    data: {
      licenseeId,
      startCode,
      endCode,
      totalCodes,
    },
  });

  const codes: Prisma.QRCodeCreateManyInput[] = [];
  for (let i = startNumber; i <= endNumber; i++) {
    codes.push({
      code: generateQRCode(licensee.prefix, i),
      licenseeId,
      status: QRStatus.DORMANT,
      tokenNonce: randomNonce(),
    });
  }

  const batchSize = 1000;
  let created = 0;
  for (let i = 0; i < codes.length; i += batchSize) {
    const chunk = codes.slice(i, i + batchSize);
    const result = await db.qRCode.createMany({ data: chunk });
    created += result.count;
  }

  let receivedBatch = null as null | { id: string; name: string };
  if (createReceivedBatch) {
    const name = `Received ${startCode} → ${endCode}`.slice(0, 120);
    const batch = await db.batch.create({
      data: {
        name,
        licenseeId,
        manufacturerId: null,
        startCode,
        endCode,
        totalCodes,
      },
      select: { id: true, name: true },
    });

    const updated = await db.qRCode.updateMany({
      where: { licenseeId, code: { gte: startCode, lte: endCode } },
      data: {
        batchId: batch.id,
        status: QRStatus.DORMANT,
      },
    });

    if (updated.count !== totalCodes) {
      throw new Error("BATCH_BUSY");
    }

    receivedBatch = batch;
  }

  await db.allocationEvent.create({
    data: {
      licenseeId,
      createdByUserId: createdByUserId || null,
      requestId: requestId || null,
      source: source || null,
      startCode,
      endCode,
      totalCodes,
    },
  });

  return { range, createdCount: created, startCode, endCode, totalCodes, receivedBatch };
};
