import {
  CustomerVerificationAuthState,
  CustomerVerificationEntryMethod,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLogSafely } from "./auditService";
import { hashToken, randomOpaqueToken } from "../utils/security";

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

const parseBoolEnv = (value: unknown, fallback: boolean) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseIntEnv = (key: string, fallback: number, min = 1, max = 24 * 365) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const VERIFY_SESSION_PROOF_BINDING_REQUIRED = parseBoolEnv(process.env.VERIFY_SESSION_PROOF_BINDING_REQUIRED, true);
const VERIFY_SESSION_PROOF_TTL_MINUTES = parseIntEnv("VERIFY_SESSION_PROOF_TTL_MINUTES", 30, 5, 24 * 60);

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const normalizeText = (value: unknown) => {
  const text = String(value || "").trim();
  return text || null;
};

const mergeSessionMetadata = (session: any, patch: Record<string, unknown>) => ({
  ...toRecord(session?.metadata),
  ...patch,
});

const toDate = (value: unknown) => {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
};

const buildSessionSummary = (params: {
  session: any;
  presentationSnapshot: Record<string, unknown> | null;
  sessionProofToken?: string | null;
}) => {
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
    challengeRequired: Boolean((presentation.challenge as Record<string, unknown> | undefined)?.required),
    challengeCompleted: Boolean((presentation.challenge as Record<string, unknown> | undefined)?.completed),
    challengeCompletedBy: normalizeText((presentation.challenge as Record<string, unknown> | undefined)?.completedBy),
    proofBindingRequired: Boolean(params.session.proofBindingTokenHash),
    proofBindingExpiresAt:
      params.session.proofBindingExpiresAt instanceof Date
        ? params.session.proofBindingExpiresAt.toISOString()
        : params.session.proofBindingExpiresAt
          ? new Date(params.session.proofBindingExpiresAt).toISOString()
          : null,
    sessionProofToken: normalizeText(params.sessionProofToken),
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
      replayEpoch:
        Number((presentationSnapshot as any).replayEpoch || 0) > 0
          ? Number((presentationSnapshot as any).replayEpoch)
          : Number(qrCode?.replayEpoch || 1),
      issuanceMode:
        normalizeText((presentationSnapshot as any).issuanceMode) ||
        normalizeText(qrCode?.issuanceMode) ||
        "LEGACY_UNSPECIFIED",
      customerVerifiableAt:
        normalizeText((presentationSnapshot as any).customerVerifiableAt) ||
        (qrCode?.customerVerifiableAt instanceof Date ? qrCode.customerVerifiableAt.toISOString() : null),
    },
  };
};

const createSessionProofBinding = (presentationSnapshot: Record<string, unknown>) => {
  const proofSource = normalizeText(presentationSnapshot.proofSource);
  if (!VERIFY_SESSION_PROOF_BINDING_REQUIRED || proofSource !== "SIGNED_LABEL") {
    return null;
  }

  const rawToken = randomOpaqueToken(24);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + VERIFY_SESSION_PROOF_TTL_MINUTES * 60_000);

  return {
    rawToken,
    tokenHash: hashToken(rawToken),
    issuedAt,
    expiresAt,
    replayEpoch:
      Number.isFinite(Number((presentationSnapshot as any).replayEpoch))
        ? Number((presentationSnapshot as any).replayEpoch)
        : 1,
  };
};

const resolveBoundSessionCustomerUserId = (session: any) =>
  normalizeText(session?.customerUserId) || normalizeText(toRecord(session?.metadata).boundCustomerUserId);

const recordSessionBoundarySignal = async (params: {
  session: any;
  customer?: CustomerIdentity | null;
  reason: string;
  phase: "LOAD" | "INTAKE" | "REVEAL" | "PROOF_BINDING";
}) => {
  await createAuditLogSafely({
    action: "CUSTOMER_VERIFICATION_SESSION_BOUNDARY_REJECTED",
    entityType: "CustomerVerificationSession",
    entityId: params.session?.id || undefined,
    details: {
      phase: params.phase,
      reason: params.reason,
      boundCustomerUserId: resolveBoundSessionCustomerUserId(params.session),
      requestedCustomerUserId: normalizeText(params.customer?.userId),
      sessionAuthState: normalizeText(params.session?.authState),
      revealed: Boolean(params.session?.revealedAt),
      intakeCompleted: Boolean(params.session?.intakeCompletedAt),
    },
  });
};

const assertSessionCustomerBinding = async (params: {
  session: any;
  customer?: CustomerIdentity | null;
  phase: "LOAD" | "INTAKE" | "REVEAL" | "PROOF_BINDING";
}) => {
  const boundCustomerUserId = resolveBoundSessionCustomerUserId(params.session);
  const requestedCustomerUserId = normalizeText(params.customer?.userId);
  const sessionRequiresBoundIdentity =
    Boolean(boundCustomerUserId) ||
    String(params.session?.authState || "").trim().toUpperCase() === CustomerVerificationAuthState.VERIFIED ||
    Boolean(params.session?.intakeCompletedAt) ||
    Boolean(params.session?.revealedAt);

  if (boundCustomerUserId && requestedCustomerUserId && boundCustomerUserId !== requestedCustomerUserId) {
    await recordSessionBoundarySignal({
      session: params.session,
      customer: params.customer,
      reason: "SESSION_CUSTOMER_MISMATCH",
      phase: params.phase,
    });
    throw new Error("Verification session belongs to a different signed-in customer.");
  }

  if (sessionRequiresBoundIdentity && !requestedCustomerUserId) {
    await recordSessionBoundarySignal({
      session: params.session,
      customer: params.customer,
      reason: "SESSION_CUSTOMER_AUTH_REQUIRED",
      phase: params.phase,
    });
    throw new Error("Customer authentication required to continue this verification session.");
  }
};

const assertSessionProofBinding = async (params: {
  session: any;
  customer?: CustomerIdentity | null;
  proofToken?: string | null;
}) => {
  await assertSessionCustomerBinding({
    session: params.session,
    customer: params.customer,
    phase: "PROOF_BINDING",
  });

  if (!params.session?.proofBindingTokenHash) return;
  if (params.session.proofBindingExpiresAt && new Date(params.session.proofBindingExpiresAt).getTime() <= Date.now()) {
    await recordSessionBoundarySignal({
      session: params.session,
      customer: params.customer,
      reason: "SESSION_PROOF_BINDING_EXPIRED",
      phase: "PROOF_BINDING",
    });
    throw new Error("Verification session expired. Re-scan the label to continue.");
  }

  const presented = normalizeText(params.proofToken);
  if (!presented) {
    await recordSessionBoundarySignal({
      session: params.session,
      customer: params.customer,
      reason: "SESSION_PROOF_BINDING_MISSING",
      phase: "PROOF_BINDING",
    });
    throw new Error("Verification session continuity check required. Re-scan the label to continue.");
  }

  if (hashToken(presented) !== params.session.proofBindingTokenHash) {
    await recordSessionBoundarySignal({
      session: params.session,
      customer: params.customer,
      reason: "SESSION_PROOF_BINDING_MISMATCH",
      phase: "PROOF_BINDING",
    });
    throw new Error("Verification session continuity check failed. Re-scan the label to continue.");
  }

  if (params.session.proofBindingReplayEpoch != null && params.session.qrCodeId && getQrStore()?.findUnique) {
    const qr = await getQrStore().findUnique({
      where: { id: params.session.qrCodeId },
      select: { replayEpoch: true },
    });
    if (qr && Number(qr.replayEpoch || 1) !== Number(params.session.proofBindingReplayEpoch)) {
      await recordSessionBoundarySignal({
        session: params.session,
        customer: params.customer,
        reason: "SESSION_REPLAY_EPOCH_MISMATCH",
        phase: "PROOF_BINDING",
      });
      throw new Error("Verification session is no longer current. Re-scan the label to continue.");
    }
  }
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

  const proofBinding = createSessionProofBinding(detail.presentationSnapshot);

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
      proofBindingTokenHash: proofBinding?.tokenHash,
      proofBindingIssuedAt: proofBinding?.issuedAt,
      proofBindingExpiresAt: proofBinding?.expiresAt,
      proofBindingReplayEpoch: proofBinding?.replayEpoch,
      metadata: {
        createdFromDecision: detail.decision.id,
        proofBindingRequired: Boolean(proofBinding),
        boundCustomerUserId: normalizeText(input.customer?.userId),
        boundCustomerEmail: normalizeText(input.customer?.email),
        identityBoundAt: input.customer?.userId ? new Date().toISOString() : null,
      },
    },
  });

  return {
    ...buildSessionSummary({
      session,
      presentationSnapshot: detail.presentationSnapshot,
      sessionProofToken: proofBinding?.rawToken || null,
    }),
    verificationLocked: true,
  };
};

export const getCustomerVerificationSession = async (input: {
  sessionId: string;
  customer?: CustomerIdentity | null;
  proofToken?: string | null;
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

  await assertSessionCustomerBinding({
    session,
    customer: input.customer || null,
    phase: "LOAD",
  });

  const detail = await loadDecisionPresentation(session.verificationDecisionId);
  if (!detail?.decision) return null;

  const canRevealVerification =
    Boolean(session.revealedAt) && (!session.customerUserId || session.customerUserId === normalizeText(input.customer?.userId));
  if (canRevealVerification) {
    await assertSessionProofBinding({
      session,
      customer: input.customer || null,
      proofToken: input.proofToken || null,
    });
  }

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
    verification: canRevealVerification ? detail.presentationSnapshot : null,
  };
};

export const saveCustomerTrustIntake = async (input: {
  sessionId: string;
  intake: TrustIntakeInput;
  customer: CustomerIdentity;
  proofToken?: string | null;
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

  await assertSessionCustomerBinding({
    session,
    customer: input.customer,
    phase: "INTAKE",
  });

  await assertSessionProofBinding({
    session,
    customer: input.customer,
    proofToken: input.proofToken || null,
  });

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
      metadata: mergeSessionMetadata(session, {
        boundCustomerUserId: normalizeText(input.customer.userId),
        boundCustomerEmail: normalizeText(input.customer.email),
        identityBoundAt: normalizeText(toRecord(session.metadata).identityBoundAt) || new Date().toISOString(),
        trustIntakeCompletedByUserId: normalizeText(input.customer.userId),
        trustIntakeCompletedAt: new Date().toISOString(),
      }),
    },
  });

  return trustIntake;
};

export const revealCustomerVerificationSession = async (input: {
  sessionId: string;
  customer: CustomerIdentity;
  proofToken?: string | null;
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

  await assertSessionCustomerBinding({
    session,
    customer: input.customer,
    phase: "REVEAL",
  });

  await assertSessionProofBinding({
    session,
    customer: input.customer,
    proofToken: input.proofToken || null,
  });

  const updated = await sessionStore.update({
    where: { id: session.id },
    data: {
      authState: CustomerVerificationAuthState.VERIFIED,
      customerUserId: normalizeText(input.customer.userId) || undefined,
      customerEmail: normalizeText(input.customer.email) || undefined,
      revealedAt: session.revealedAt || new Date(),
      metadata: mergeSessionMetadata(session, {
        boundCustomerUserId: normalizeText(input.customer.userId),
        boundCustomerEmail: normalizeText(input.customer.email),
        identityBoundAt: normalizeText(toRecord(session.metadata).identityBoundAt) || new Date().toISOString(),
        revealCompletedByUserId: normalizeText(input.customer.userId),
        revealCompletedAt: new Date().toISOString(),
      }),
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
