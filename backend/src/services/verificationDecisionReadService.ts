import {
  CustomerTrustLevel,
  CustomerTrustReviewState,
  VerificationDecisionOutcome,
  VerificationDegradationMode,
  VerificationProofTier,
  VerificationReplacementStatus,
  VerificationRiskBand,
} from "@prisma/client";

import prisma from "../config/database";

export type InternalLatestDecision = {
  decisionId: string;
  decisionVersion: number;
  outcome: VerificationDecisionOutcome;
  proofTier: VerificationProofTier;
  riskBand: VerificationRiskBand;
  replacementStatus: VerificationReplacementStatus;
  customerTrustLevel: CustomerTrustLevel;
  customerTrustReviewState: CustomerTrustReviewState;
  printTrustState: string | null;
  labelState: string | null;
  reasonCodes: string[];
  verifiedAt: string;
  degradationMode: VerificationDegradationMode;
  replacementChainId: string | null;
  customerTrustCredentialId: string | null;
};

const decisionStore = () => (prisma as any).verificationDecision;
const evidenceStore = () => (prisma as any).verificationEvidenceSnapshot;
const trustStore = () => (prisma as any).customerTrustCredential;

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const mapDecision = (params: {
  decision: any;
  evidenceByDecisionId: Map<string, any>;
  trustByQrCodeId: Map<string, any>;
}): InternalLatestDecision => {
  const evidence = params.evidenceByDecisionId.get(params.decision.id);
  const lifecycle = toRecord(evidence?.lifecycleSnapshot);
  const metadata = toRecord(params.decision.metadata);
  const trust = params.decision.qrCodeId ? params.trustByQrCodeId.get(params.decision.qrCodeId) : null;

  return {
    decisionId: params.decision.id,
    decisionVersion: Number(params.decision.decisionVersion || 1),
    outcome: params.decision.outcome,
    proofTier: params.decision.proofTier,
    riskBand: params.decision.riskBand,
    replacementStatus: params.decision.replacementStatus,
    customerTrustLevel: trust?.trustLevel || params.decision.customerTrustLevel,
    customerTrustReviewState: trust?.reviewState || CustomerTrustReviewState.UNREVIEWED,
    printTrustState: String(lifecycle.printTrustState || "").trim() || null,
    labelState: String(lifecycle.labelState || "").trim() || null,
    reasonCodes: Array.isArray(params.decision.reasonCodes) ? params.decision.reasonCodes.filter(Boolean) : [],
    verifiedAt: params.decision.createdAt instanceof Date ? params.decision.createdAt.toISOString() : new Date(params.decision.createdAt).toISOString(),
    degradationMode: params.decision.degradationMode || VerificationDegradationMode.NORMAL,
    replacementChainId: String(metadata.replacementChainId || "").trim() || null,
    customerTrustCredentialId: String(trust?.id || "").trim() || null,
  };
};

const loadEvidenceByDecisionIds = async (decisionIds: string[]) => {
  const store = evidenceStore();
  if (!decisionIds.length || !store?.findMany) return new Map<string, any>();

  const rows = await store.findMany({
    where: {
      verificationDecisionId: { in: decisionIds },
    },
    orderBy: [{ createdAt: "desc" }],
  });

  const map = new Map<string, any>();
  for (const row of rows) {
    if (!row?.verificationDecisionId || map.has(row.verificationDecisionId)) continue;
    map.set(row.verificationDecisionId, row);
  }
  return map;
};

const loadTrustByQrCodeIds = async (qrCodeIds: string[]) => {
  const store = trustStore();
  if (!qrCodeIds.length || !store?.findMany) return new Map<string, any>();

  const rows = await store.findMany({
    where: {
      qrCodeId: { in: qrCodeIds },
    },
    orderBy: [{ updatedAt: "desc" }],
  });

  const map = new Map<string, any>();
  for (const row of rows) {
    if (!row?.qrCodeId || map.has(row.qrCodeId)) continue;
    map.set(row.qrCodeId, row);
  }
  return map;
};

export const listLatestDecisionByQrCodeIds = async (qrCodeIds: string[]) => {
  const store = decisionStore();
  const normalizedQrCodeIds = Array.from(new Set(qrCodeIds.map((value) => String(value || "").trim()).filter(Boolean)));
  const out = new Map<string, InternalLatestDecision>();

  if (!normalizedQrCodeIds.length || !store?.findMany) return out;

  const rows = await store.findMany({
    where: {
      qrCodeId: { in: normalizedQrCodeIds },
    },
    orderBy: [{ qrCodeId: "asc" }, { createdAt: "desc" }],
  });

  const latestRows: any[] = [];
  const seenQrCodeIds = new Set<string>();
  for (const row of rows) {
    const qrCodeId = String(row?.qrCodeId || "").trim();
    if (!qrCodeId || seenQrCodeIds.has(qrCodeId)) continue;
    seenQrCodeIds.add(qrCodeId);
    latestRows.push(row);
  }

  const evidenceByDecisionId = await loadEvidenceByDecisionIds(latestRows.map((row) => row.id));
  const trustByQrCodeId = await loadTrustByQrCodeIds(latestRows.map((row) => String(row.qrCodeId || "")));

  for (const row of latestRows) {
    out.set(String(row.qrCodeId), mapDecision({ decision: row, evidenceByDecisionId, trustByQrCodeId }));
  }

  return out;
};

export const listLatestDecisionByBatchIds = async (batchIds: string[]) => {
  const store = decisionStore();
  const normalizedBatchIds = Array.from(new Set(batchIds.map((value) => String(value || "").trim()).filter(Boolean)));
  const out = new Map<string, InternalLatestDecision>();

  if (!normalizedBatchIds.length || !store?.findMany) return out;

  const rows = await store.findMany({
    where: {
      batchId: { in: normalizedBatchIds },
    },
    orderBy: [{ batchId: "asc" }, { createdAt: "desc" }],
  });

  const latestRows: any[] = [];
  const seenBatchIds = new Set<string>();
  for (const row of rows) {
    const batchId = String(row?.batchId || "").trim();
    if (!batchId || seenBatchIds.has(batchId)) continue;
    seenBatchIds.add(batchId);
    latestRows.push(row);
  }

  const evidenceByDecisionId = await loadEvidenceByDecisionIds(latestRows.map((row) => row.id));
  const trustByQrCodeId = await loadTrustByQrCodeIds(
    latestRows.map((row) => String(row.qrCodeId || "").trim()).filter(Boolean)
  );

  for (const row of latestRows) {
    out.set(String(row.batchId), mapDecision({ decision: row, evidenceByDecisionId, trustByQrCodeId }));
  }

  return out;
};
