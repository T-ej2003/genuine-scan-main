import {
  CustomerVerificationAuthState,
  CustomerVerificationEntryMethod,
} from "@prisma/client";

import prisma from "../config/database";

type CustomerIdentity = {
  userId?: string | null;
  email?: string | null;
};

type TrustIntakeInput = {
  purchaseChannel: string;
  sourceCategory?: string | null;
  platformName?: string | null;
  sellerName?: string | null;
  listingUrl?: string | null;
  orderReference?: string | null;
  storeName?: string | null;
  purchaseCity?: string | null;
  purchaseCountry?: string | null;
  purchaseDate?: Date | string | null;
  packagingState?: string | null;
  packagingConcern?: string | null;
  scanReason: string;
  ownershipIntent: string;
  notes?: string | null;
  answers?: Record<string, unknown> | null;
};

const getDecisionStore = () => (prisma as any).verificationDecision;
const getEvidenceStore = () => (prisma as any).verificationEvidenceSnapshot;
const getSessionStore = () => (prisma as any).customerVerificationSession;
const getIntakeStore = () => (prisma as any).customerTrustIntake;
const getQrStore = () => (prisma as any).qRCode;

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const normalizeText = (value: unknown) => {
  const text = String(value || "").trim();
  return text || null;
};

const toDate = (value: unknown) => {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
};

const buildSessionSummary = (params: { session: any; presentationSnapshot: Record<string, unknown> | null }) => {
  const presentation = params.presentationSnapshot || {};
  const code = normalizeText(params.session?.code) || normalizeText(presentation.code) || null;
  const maskedCode = code ? `${code.slice(0, Math.min(4, code.length))}${code.length > 4 ? `-${code.slice(-4)}` : ""}` : null;

  return {
    sessionId: params.session.id,
    decisionId: params.session.verificationDecisionId,
    code,
    maskedCode,
    entryMethod: params.session.entryMethod,
    authState: params.session.authState,
    intakeCompleted: Boolean(params.session.intakeCompletedAt),
    revealed: Boolean(params.session.revealedAt),
    startedAt:
      params.session.createdAt instanceof Date ? params.session.createdAt.toISOString() : new Date(params.session.createdAt).toISOString(),
    revealAt:
      params.session.revealedAt instanceof Date
        ? params.session.revealedAt.toISOString()
        : params.session.revealedAt
          ? new Date(params.session.revealedAt).toISOString()
          : null,
    brandName:
      normalizeText((presentation.licensee as Record<string, unknown> | undefined)?.brandName) ||
      normalizeText((presentation.licensee as Record<string, unknown> | undefined)?.name),
    proofTier: normalizeText(presentation.proofTier),
    proofSource: normalizeText(presentation.proofSource),
    labelState: normalizeText(presentation.labelState),
    printTrustState: normalizeText(presentation.printTrustState),
  };
};

const loadDecisionPresentation = async (decisionId: string) => {
  const normalizedDecisionId = String(decisionId || "").trim();
  if (!normalizedDecisionId) return null;

  const [decision, evidence] = await Promise.all([
    getDecisionStore()?.findUnique?.({
      where: { id: normalizedDecisionId },
    }),
    getEvidenceStore()?.findFirst?.({
      where: { verificationDecisionId: normalizedDecisionId },
      orderBy: [{ createdAt: "desc" }],
    }),
  ]);

  if (!decision) return null;

  const evidenceMetadata = toRecord(evidence?.metadata);
  const presentationSnapshot = toRecord(evidenceMetadata.presentationSnapshot);
  const qrCode =
    decision.qrCodeId && getQrStore()?.findUnique
      ? await getQrStore().findUnique({
          where: { id: decision.qrCodeId },
          include: {
            licensee: {
              select: {
                id: true,
                name: true,
                brandName: true,
                prefix: true,
                supportEmail: true,
                supportPhone: true,
                website: true,
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
                    location: true,
                    website: true,
                    email: true,
                  },
                },
              },
            },
          },
        })
      : null;

  return {
    decision,
    presentationSnapshot: {
      ...presentationSnapshot,
      code: normalizeText((presentationSnapshot as any).code) || normalizeText(decision.code),
      licensee:
        presentationSnapshot.licensee ||
        (qrCode?.licensee
          ? {
              id: qrCode.licensee.id,
              name: qrCode.licensee.name,
              brandName: qrCode.licensee.brandName,
              prefix: qrCode.licensee.prefix,
              supportEmail: qrCode.licensee.supportEmail,
              supportPhone: qrCode.licensee.supportPhone,
              website: qrCode.licensee.website,
            }
          : null),
      batch:
        presentationSnapshot.batch ||
        (qrCode?.batch
          ? {
              id: qrCode.batch.id,
              name: qrCode.batch.name,
              printedAt: qrCode.batch.printedAt,
              manufacturer: qrCode.batch.manufacturer || null,
            }
          : null),
    },
  };
};

export const createCustomerVerificationSession = async (input: {
  decisionId: string;
  entryMethod: CustomerVerificationEntryMethod;
  customer?: CustomerIdentity | null;
}) => {
  const sessionStore = getSessionStore();
  if (!sessionStore?.create) {
    throw new Error("Customer verification session storage unavailable");
  }

  const detail = await loadDecisionPresentation(input.decisionId);
  if (!detail?.decision) {
    throw new Error("Verification decision not found");
  }

  const session = await sessionStore.create({
    data: {
      verificationDecisionId: detail.decision.id,
      qrCodeId: detail.decision.qrCodeId || undefined,
      code: normalizeText(detail.presentationSnapshot.code) || detail.decision.code || undefined,
      entryMethod: input.entryMethod,
      authState: input.customer?.userId ? CustomerVerificationAuthState.VERIFIED : CustomerVerificationAuthState.PENDING,
      customerUserId: normalizeText(input.customer?.userId) || undefined,
      customerEmail: normalizeText(input.customer?.email) || undefined,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
      metadata: {
        createdFromDecision: detail.decision.id,
      },
    },
  });

  return {
    ...buildSessionSummary({ session, presentationSnapshot: detail.presentationSnapshot }),
    verificationLocked: true,
  };
};

export const getCustomerVerificationSession = async (input: {
  sessionId: string;
  customer?: CustomerIdentity | null;
}) => {
  const sessionStore = getSessionStore();
  if (!sessionStore?.findUnique) return null;

  const session = await sessionStore.findUnique({
    where: { id: String(input.sessionId || "").trim() },
    include: {
      trustIntake: true,
    },
  });
  if (!session) return null;

  const detail = await loadDecisionPresentation(session.verificationDecisionId);
  if (!detail?.decision) return null;

  return {
    ...buildSessionSummary({ session, presentationSnapshot: detail.presentationSnapshot }),
    intake: session.trustIntake
      ? {
          purchaseChannel: session.trustIntake.purchaseChannel,
          sourceCategory: session.trustIntake.sourceCategory,
          platformName: session.trustIntake.platformName,
          sellerName: session.trustIntake.sellerName,
          listingUrl: session.trustIntake.listingUrl,
          orderReference: session.trustIntake.orderReference,
          storeName: session.trustIntake.storeName,
          purchaseCity: session.trustIntake.purchaseCity,
          purchaseCountry: session.trustIntake.purchaseCountry,
          purchaseDate: session.trustIntake.purchaseDate ? session.trustIntake.purchaseDate.toISOString() : null,
          packagingState: session.trustIntake.packagingState,
          packagingConcern: session.trustIntake.packagingConcern,
          scanReason: session.trustIntake.scanReason,
          ownershipIntent: session.trustIntake.ownershipIntent,
          notes: session.trustIntake.notes,
          answers: session.trustIntake.answers || null,
        }
      : null,
    verification:
      session.revealedAt && (!session.customerUserId || session.customerUserId === normalizeText(input.customer?.userId))
        ? detail.presentationSnapshot
        : null,
  };
};

export const saveCustomerTrustIntake = async (input: {
  sessionId: string;
  intake: TrustIntakeInput;
  customer: CustomerIdentity;
}) => {
  const sessionStore = getSessionStore();
  const intakeStore = getIntakeStore();
  if (!sessionStore?.findUnique || !sessionStore?.update || !intakeStore?.upsert) {
    throw new Error("Customer verification intake storage unavailable");
  }

  const session = await sessionStore.findUnique({
    where: { id: String(input.sessionId || "").trim() },
  });
  if (!session) {
    throw new Error("Verification session not found");
  }

  const nextPurchaseDate = toDate(input.intake.purchaseDate);

  const trustIntake = await intakeStore.upsert({
    where: { sessionId: session.id },
    create: {
      sessionId: session.id,
      customerUserId: normalizeText(input.customer.userId) || undefined,
      customerEmail: normalizeText(input.customer.email) || undefined,
      purchaseChannel: input.intake.purchaseChannel,
      sourceCategory: normalizeText(input.intake.sourceCategory) || undefined,
      platformName: normalizeText(input.intake.platformName) || undefined,
      sellerName: normalizeText(input.intake.sellerName) || undefined,
      listingUrl: normalizeText(input.intake.listingUrl) || undefined,
      orderReference: normalizeText(input.intake.orderReference) || undefined,
      storeName: normalizeText(input.intake.storeName) || undefined,
      purchaseCity: normalizeText(input.intake.purchaseCity) || undefined,
      purchaseCountry: normalizeText(input.intake.purchaseCountry) || undefined,
      purchaseDate: nextPurchaseDate || undefined,
      packagingState: normalizeText(input.intake.packagingState) || undefined,
      packagingConcern: normalizeText(input.intake.packagingConcern) || undefined,
      scanReason: input.intake.scanReason,
      ownershipIntent: input.intake.ownershipIntent,
      notes: normalizeText(input.intake.notes) || undefined,
      answers: input.intake.answers || undefined,
    },
    update: {
      customerUserId: normalizeText(input.customer.userId) || undefined,
      customerEmail: normalizeText(input.customer.email) || undefined,
      purchaseChannel: input.intake.purchaseChannel,
      sourceCategory: normalizeText(input.intake.sourceCategory) || null,
      platformName: normalizeText(input.intake.platformName) || null,
      sellerName: normalizeText(input.intake.sellerName) || null,
      listingUrl: normalizeText(input.intake.listingUrl) || null,
      orderReference: normalizeText(input.intake.orderReference) || null,
      storeName: normalizeText(input.intake.storeName) || null,
      purchaseCity: normalizeText(input.intake.purchaseCity) || null,
      purchaseCountry: normalizeText(input.intake.purchaseCountry) || null,
      purchaseDate: nextPurchaseDate,
      packagingState: normalizeText(input.intake.packagingState) || null,
      packagingConcern: normalizeText(input.intake.packagingConcern) || null,
      scanReason: input.intake.scanReason,
      ownershipIntent: input.intake.ownershipIntent,
      notes: normalizeText(input.intake.notes) || null,
      answers: input.intake.answers || null,
    },
  });

  await sessionStore.update({
    where: { id: session.id },
    data: {
      authState: CustomerVerificationAuthState.VERIFIED,
      customerUserId: normalizeText(input.customer.userId) || undefined,
      customerEmail: normalizeText(input.customer.email) || undefined,
      intakeCompletedAt: new Date(),
    },
  });

  return trustIntake;
};

export const revealCustomerVerificationSession = async (input: {
  sessionId: string;
  customer: CustomerIdentity;
}) => {
  const sessionStore = getSessionStore();
  if (!sessionStore?.findUnique || !sessionStore?.update) {
    throw new Error("Customer verification session storage unavailable");
  }

  const session = await sessionStore.findUnique({
    where: { id: String(input.sessionId || "").trim() },
    include: {
      trustIntake: true,
    },
  });
  if (!session) {
    throw new Error("Verification session not found");
  }
  if (!session.trustIntake) {
    throw new Error("Verification intake must be completed before reveal");
  }

  const updated = await sessionStore.update({
    where: { id: session.id },
    data: {
      authState: CustomerVerificationAuthState.VERIFIED,
      customerUserId: normalizeText(input.customer.userId) || undefined,
      customerEmail: normalizeText(input.customer.email) || undefined,
      revealedAt: session.revealedAt || new Date(),
    },
    include: {
      trustIntake: true,
    },
  });

  const detail = await loadDecisionPresentation(updated.verificationDecisionId);
  if (!detail?.decision) {
    throw new Error("Locked verification decision unavailable");
  }

  return {
    ...buildSessionSummary({ session: updated, presentationSnapshot: detail.presentationSnapshot }),
    verification: detail.presentationSnapshot,
    intake: updated.trustIntake
      ? {
          purchaseChannel: updated.trustIntake.purchaseChannel,
          sourceCategory: updated.trustIntake.sourceCategory,
          platformName: updated.trustIntake.platformName,
          sellerName: updated.trustIntake.sellerName,
          listingUrl: updated.trustIntake.listingUrl,
          orderReference: updated.trustIntake.orderReference,
          storeName: updated.trustIntake.storeName,
          purchaseCity: updated.trustIntake.purchaseCity,
          purchaseCountry: updated.trustIntake.purchaseCountry,
          purchaseDate: updated.trustIntake.purchaseDate ? updated.trustIntake.purchaseDate.toISOString() : null,
          packagingState: updated.trustIntake.packagingState,
          packagingConcern: updated.trustIntake.packagingConcern,
          scanReason: updated.trustIntake.scanReason,
          ownershipIntent: updated.trustIntake.ownershipIntent,
          notes: updated.trustIntake.notes,
          answers: updated.trustIntake.answers || null,
        }
      : null,
  };
};
