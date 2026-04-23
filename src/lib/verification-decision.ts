export type CustomerTrustLevel =
  | "ANONYMOUS"
  | "DEVICE_TRUSTED"
  | "ACCOUNT_TRUSTED"
  | "PASSKEY_VERIFIED"
  | "OPERATOR_REVIEWED";

export type CustomerTrustReviewState = "UNREVIEWED" | "VERIFIED" | "DISPUTED" | "REVOKED";

export type LatestDecision = {
  decisionId: string;
  decisionVersion: number;
  outcome: string;
  proofTier: "SIGNED_LABEL" | "MANUAL_REGISTRY_LOOKUP" | "DEGRADED";
  publicOutcome?: string | null;
  riskDisposition?: string | null;
  messageKey?: string | null;
  riskBand: "LOW" | "ELEVATED" | "HIGH" | "CRITICAL";
  replacementStatus: "NONE" | "ACTIVE_REPLACEMENT" | "REPLACED_LABEL";
  customerTrustLevel: CustomerTrustLevel;
  customerTrustReviewState: CustomerTrustReviewState;
  printTrustState?: string | null;
  labelState?: string | null;
  reasonCodes?: string[];
  verifiedAt: string;
  degradationMode?: "NORMAL" | "QUEUE_AND_RETRY" | "FAIL_CLOSED";
  replacementChainId?: string | null;
  customerTrustCredentialId?: string | null;
};

export const titleCaseDecisionValue = (value?: string | null) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

export type PrintTrustPresentation = {
  label: string;
  tone: string;
  guidance: string;
  emphasis: "governed" | "limited" | "restricted" | "pending" | "neutral";
};

export const presentPrintTrustState = (
  decision?: Pick<LatestDecision, "printTrustState" | "publicOutcome" | "messageKey"> | null
): PrintTrustPresentation => {
  const normalizedState = String(decision?.printTrustState || "").trim().toUpperCase();
  const normalizedOutcome = String(decision?.publicOutcome || "").trim().toUpperCase();

  if (normalizedState === "PRINT_CONFIRMED") {
    return {
      label: "Governed print confirmed",
      tone: "border-emerald-200 bg-emerald-50 text-emerald-700",
      guidance: "This label followed the governed print path and reached customer-verifiable readiness.",
      emphasis: "governed",
    };
  }

  if (normalizedState === "LIMITED_PROVENANCE" || normalizedOutcome === "LIMITED_PROVENANCE") {
    return {
      label: "Limited provenance",
      tone: "border-amber-200 bg-amber-50 text-amber-800",
      guidance: "MSCQR can still check this label record, but governed print provenance is incomplete or legacy.",
      emphasis: "limited",
    };
  }

  if (normalizedState === "LEGACY_NO_CONTROLLED_PRINT") {
    return {
      label: "Legacy label without governed print",
      tone: "border-amber-200 bg-amber-50 text-amber-800",
      guidance: "Treat this as a legacy record. Do not present it as equivalent to governed print confirmation.",
      emphasis: "limited",
    };
  }

  if (normalizedState === "RESTRICTED_DIRECT_ISSUANCE") {
    return {
      label: "Restricted direct issuance",
      tone: "border-rose-200 bg-rose-50 text-rose-700",
      guidance: "This label came from a restricted break-glass path and should stay outside normal premium issuance claims.",
      emphasis: "restricted",
    };
  }

  if (normalizedState === "AWAITING_PRINT_CONFIRMATION") {
    return {
      label: "Awaiting print confirmation",
      tone: "border-slate-300 bg-slate-100 text-slate-700",
      guidance: "The label exists, but MSCQR has not yet confirmed customer-verifiable print readiness.",
      emphasis: "pending",
    };
  }

  return {
    label: normalizedState ? titleCaseDecisionValue(normalizedState) : "Governed print status unavailable",
    tone: "border-slate-300 bg-slate-100 text-slate-700",
    guidance: "No curated governed-print trust signal is available for this decision yet.",
    emphasis: "neutral",
  };
};

export const decisionOutcomeTone = (value?: string | null) => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "AUTHENTIC") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (normalized === "SUSPICIOUS_DUPLICATE") return "border-amber-200 bg-amber-50 text-amber-700";
  if (normalized === "BLOCKED") return "border-rose-200 bg-rose-50 text-rose-700";
  if (normalized === "NOT_READY") return "border-slate-300 bg-slate-100 text-slate-700";
  return "border-slate-300 bg-slate-100 text-slate-700";
};

export const decisionRiskTone = (value?: string | null) => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "CRITICAL") return "border-rose-200 bg-rose-50 text-rose-700";
  if (normalized === "HIGH") return "border-orange-200 bg-orange-50 text-orange-700";
  if (normalized === "ELEVATED") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
};

export const decisionTrustTone = (value?: string | null) => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "REVOKED") return "border-rose-200 bg-rose-50 text-rose-700";
  if (normalized === "DISPUTED") return "border-amber-200 bg-amber-50 text-amber-700";
  if (normalized === "VERIFIED") return "border-cyan-200 bg-cyan-50 text-cyan-700";
  return "border-slate-300 bg-slate-100 text-slate-700";
};
