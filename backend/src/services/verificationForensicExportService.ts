import { createHash } from "crypto";

import prisma from "../config/database";

const getDecisionStore = () => (prisma as any).verificationDecision;
const getEvidenceStore = () => (prisma as any).verificationEvidenceSnapshot;

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const normalizeText = (value: unknown) => {
  const text = String(value || "").trim();
  return text || null;
};

const hashRef = (prefix: string, value: unknown) => {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  return `${prefix}_${createHash("sha256").update(normalized).digest("hex").slice(0, 12)}`;
};

const sanitizeValue = (value: unknown, depth = 0): unknown => {
  if (value == null) return null;
  if (depth >= 4) return "[truncated]";
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") {
    const normalized = value.trim();
    if (!normalized) return null;
    if (/^[A-Z0-9_:-]{1,96}$/i.test(normalized)) return normalized;
    return hashRef("str", normalized);
  }
  if (Array.isArray(value)) return value.slice(0, 20).map((entry) => sanitizeValue(entry, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, 40)) {
      if (/(email|token|secret|password|cookie|session|proof|customer|user|device|ip|id)$/i.test(key)) continue;
      out[key] = sanitizeValue(entry, depth + 1);
    }
    return out;
  }
  return String(value);
};

export const buildVerificationForensicExportV2 = async (decisionId: string) => {
  const normalizedDecisionId = String(decisionId || "").trim();
  if (!normalizedDecisionId) {
    throw new Error("Verification decision id is required");
  }

  const decision = await getDecisionStore()?.findUnique?.({
    where: { id: normalizedDecisionId },
  });
  if (!decision) {
    throw new Error("Verification decision not found");
  }

  const evidence = await getEvidenceStore()?.findFirst?.({
    where: { verificationDecisionId: normalizedDecisionId },
    orderBy: [{ createdAt: "desc" }],
  });

  const decisionMetadata = toRecord(decision.metadata);
  const evidenceMetadata = toRecord(evidence?.metadata);
  const lifecycleSnapshot = toRecord(evidence?.lifecycleSnapshot || evidenceMetadata.lifecycleSnapshot);
  const ownershipSnapshot = toRecord(evidence?.ownershipSnapshot || evidenceMetadata.ownershipSnapshot);
  const riskSignals = toRecord(evidence?.riskSignals || evidenceMetadata.riskSignals);
  const policySnapshot = toRecord(evidence?.policySnapshot || evidenceMetadata.policySnapshot);
  const scanSummary = toRecord(evidence?.scanSummary || evidenceMetadata.scanSummary);
  const signing = toRecord(decisionMetadata.signing);
  const replayAssessment = toRecord(decisionMetadata.replayAssessment);

  return {
    schemaVersion: "verification-forensic-export.v2",
    exportedAt: new Date().toISOString(),
    decision: {
      id: decision.id,
      createdAt: decision.createdAt instanceof Date ? decision.createdAt.toISOString() : String(decision.createdAt || ""),
      proofTier: decision.proofTier,
      proofSource: decision.proofSource || null,
      classification: decision.classification || null,
      publicOutcome: normalizeText((decision as any).publicOutcome),
      riskDisposition: normalizeText((decision as any).riskDisposition),
      riskBand: decision.riskBand,
      reasonCodes: Array.isArray(decision.reasonCodes) ? decision.reasonCodes : [],
      messageKey: normalizeText((decision as any).messageKey),
      nextActionKey: normalizeText((decision as any).nextActionKey),
    },
    lifecycle: {
      labelState: normalizeText(lifecycleSnapshot.labelState),
      printTrustState: normalizeText(lifecycleSnapshot.printTrustState),
      issuanceMode: normalizeText(lifecycleSnapshot.issuanceMode),
      customerVerifiableAt: normalizeText(lifecycleSnapshot.customerVerifiableAt),
      replacementStatus: normalizeText(lifecycleSnapshot.replacementStatus),
      replayEpoch: Number(lifecycleSnapshot.replayEpoch || 0) || null,
      replayState: normalizeText(lifecycleSnapshot.replayState || replayAssessment.replayState),
      breakGlassUsage:
        String(lifecycleSnapshot.issuanceMode || "").trim().toUpperCase() === "BREAK_GLASS_DIRECT" ||
        String(lifecycleSnapshot.printTrustState || "").trim().toUpperCase() === "RESTRICTED_DIRECT_ISSUANCE",
      limitedProvenance:
        String((decision as any).publicOutcome || "").trim().toUpperCase() === "LIMITED_PROVENANCE" ||
        String(lifecycleSnapshot.printTrustState || "").trim().toUpperCase() === "LIMITED_PROVENANCE",
    },
    challenge: {
      required: Boolean(decisionMetadata.stepUpRequired),
      completed: Boolean(decisionMetadata.stepUpSatisfied),
      completedBy: normalizeText(decisionMetadata.stepUpCompletedBy),
    },
    signing: {
      mode: normalizeText(signing.mode),
      provider: normalizeText(signing.provider),
      keyVersion: normalizeText(signing.keyVersion),
      payloadKeyVersion: normalizeText(signing.payloadKeyVersion),
      keyRef: normalizeText(signing.keyRef),
      legacyHmacFallback: Boolean(signing.legacyHmacFallback),
    },
    actor: {
      actorIpRef: hashRef("actor_ip", (decision as any).actorIpHash),
      actorDeviceRef: hashRef("actor_device", (decision as any).actorDeviceHash),
      customerUserRef: hashRef("cust", decisionMetadata.customerUserId),
      ownershipRef: hashRef("owner", ownershipSnapshot.ownershipId),
      ownershipMatchMethod: normalizeText(ownershipSnapshot.matchMethod),
    },
    evidence: {
      scanSummary: sanitizeValue(scanSummary),
      ownershipSnapshot: sanitizeValue(ownershipSnapshot),
      riskSignals: sanitizeValue(riskSignals),
      policySnapshot: sanitizeValue(policySnapshot),
      replayAssessment: sanitizeValue(replayAssessment),
    },
    privacy: {
      rawCustomerDataIncluded: false,
      rawIpIncluded: false,
      rawDeviceFingerprintIncluded: false,
      redactionStrategy: "hashed_references_and_sanitized_metadata",
    },
  };
};
