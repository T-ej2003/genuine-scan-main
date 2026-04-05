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
