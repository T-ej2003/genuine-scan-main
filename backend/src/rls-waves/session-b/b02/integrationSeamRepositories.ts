import { Prisma } from "@prisma/client";

import {
  B02PublicFunctionClient,
  submitPublicIncident,
  verifyRawQr,
} from "./publicBoundaryRepository";

export const submitIncidentThroughPublicBoundary = (
  db: B02PublicFunctionClient,
  input: Parameters<typeof submitPublicIncident>[1]
) => submitPublicIncident(db, input);

export const resolvePublicVerificationThroughBoundary = (
  db: B02PublicFunctionClient,
  input: Parameters<typeof verifyRawQr>[1]
) => verifyRawQr(db, input);

export const readVerifiedQrPolicyInputs = async (
  tx: Prisma.TransactionClient,
  input: { qrCodeId: string; licenseeId: string }
) => {
  const qr = await tx.qRCode.findFirst({
    where: { id: input.qrCodeId, licenseeId: input.licenseeId },
    select: { id: true, licenseeId: true },
  });
  if (!qr) throw new Error("Verified QR scope is stale or foreign");
  return tx.tenantFeatureFlag.findMany({
    where: { licenseeId: qr.licenseeId },
    select: { key: true, enabled: true, config: true },
    orderBy: [{ key: "asc" }],
  });
};

export const readVerifiedReplacementStatus = async (
  tx: Prisma.TransactionClient,
  input: { qrCodeId: string }
) => tx.replacementChain.findFirst({
  where: {
    OR: [
      { originalQrCodeId: input.qrCodeId },
      { replacementQrCodeId: input.qrCodeId },
    ],
    status: "ACTIVE",
  },
  select: {
    id: true,
    originalQrCodeId: true,
    replacementQrCodeId: true,
    status: true,
  },
  orderBy: [{ createdAt: "desc" }],
});

