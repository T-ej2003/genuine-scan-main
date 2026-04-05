import { QRStatus, ReplacementChainStatus, VerificationReplacementStatus } from "@prisma/client";

import prisma from "../config/database";

const getStore = (client: any = prisma) => client?.replacementChain;

export const resolveReplacementStatus = async (qrCodeId: string) => {
  const store = getStore();
  if (!store?.findFirst) {
    return {
      replacementStatus: VerificationReplacementStatus.NONE,
      replacementChainId: null as string | null,
      relatedQrCodeId: null as string | null,
    };
  }

  try {
    const replaced = await store.findFirst({
      where: {
        originalQrCodeId: qrCodeId,
        status: ReplacementChainStatus.ACTIVE,
      },
      orderBy: [{ createdAt: "desc" }],
    });
    if (replaced?.id) {
      return {
        replacementStatus: VerificationReplacementStatus.REPLACED_LABEL,
        replacementChainId: replaced.id as string,
        relatedQrCodeId: String(replaced.replacementQrCodeId || "") || null,
      };
    }

    const replacement = await store.findFirst({
      where: {
        replacementQrCodeId: qrCodeId,
        status: ReplacementChainStatus.ACTIVE,
      },
      orderBy: [{ createdAt: "desc" }],
    });
    if (replacement?.id) {
      return {
        replacementStatus: VerificationReplacementStatus.ACTIVE_REPLACEMENT,
        replacementChainId: replacement.id as string,
        relatedQrCodeId: String(replacement.originalQrCodeId || "") || null,
      };
    }
  } catch (error) {
    console.warn("replacement chain resolution skipped:", error);
  }

  return {
    replacementStatus: VerificationReplacementStatus.NONE,
    replacementChainId: null as string | null,
    relatedQrCodeId: null as string | null,
  };
};

export const materializeReplacementChainsForReissue = async (params: {
  tx?: any;
  originalPrintJobId: string;
  replacementPrintJobId: string;
  reissueRequestId?: string | null;
  reason?: string | null;
}) => {
  const tx = params.tx || prisma;
  const store = getStore(tx);
  if (!store?.upsert || !tx?.qRCode?.findMany || !tx?.qRCode?.updateMany) return [];

  const [originalQrs, replacementQrs] = await Promise.all([
    tx.qRCode.findMany({
      where: { printJobId: params.originalPrintJobId },
      orderBy: [{ code: "asc" }],
      select: { id: true, code: true },
    }),
    tx.qRCode.findMany({
      where: { printJobId: params.replacementPrintJobId },
      orderBy: [{ code: "asc" }],
      select: { id: true, code: true },
    }),
  ]);

  const pairCount = Math.min(originalQrs.length, replacementQrs.length);
  if (pairCount <= 0) return [];

  const created = [];
  const now = new Date();

  for (let index = 0; index < pairCount; index += 1) {
    const original = originalQrs[index];
    const replacement = replacementQrs[index];
    if (!original?.id || !replacement?.id) continue;

    const row = await store.upsert({
      where: { replacementQrCodeId: replacement.id },
      update: {
        status: ReplacementChainStatus.ACTIVE,
        originalQrCodeId: original.id,
        originalPrintJobId: params.originalPrintJobId,
        replacementPrintJobId: params.replacementPrintJobId,
        reissueRequestId: params.reissueRequestId || undefined,
        reason: params.reason || undefined,
        supersededAt: null,
        metadata: {
          originalCode: original.code,
          replacementCode: replacement.code,
        },
      },
      create: {
        status: ReplacementChainStatus.ACTIVE,
        originalQrCodeId: original.id,
        replacementQrCodeId: replacement.id,
        originalPrintJobId: params.originalPrintJobId,
        replacementPrintJobId: params.replacementPrintJobId,
        reissueRequestId: params.reissueRequestId || undefined,
        reason: params.reason || undefined,
        metadata: {
          originalCode: original.code,
          replacementCode: replacement.code,
        },
      },
    });
    created.push(row);

    await tx.qRCode.updateMany({
      where: {
        id: original.id,
        status: { not: QRStatus.BLOCKED },
      },
      data: {
        status: QRStatus.BLOCKED,
        blockedAt: now,
        underInvestigationAt: now,
        underInvestigationReason: "Superseded by controlled replacement issuance.",
      },
    });
  }

  return created;
};
