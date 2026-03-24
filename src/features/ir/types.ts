export type LicenseeLite = { id: string; name: string; prefix: string };

export type IncidentFiltersState = {
  status: string;
  severity: string;
  priority: string;
  licenseeId: string;
  search: string;
};

export type AlertFiltersState = {
  acknowledged: string;
  severity: string;
  alertType: string;
  licenseeId: string;
};

export type NewIncidentState = {
  qrCodeValue: string;
  incidentType: string;
  severity: string;
  priority: string;
  licenseeId: string;
  description: string;
};

export type PolicyFormState = {
  name: string;
  description: string;
  ruleType: string;
  isActive: boolean;
  threshold: string;
  windowMinutes: string;
  severity: string;
  autoCreateIncident: boolean;
  incidentSeverity: string;
  incidentPriority: string;
  licenseeId: string;
};

export const STATUS_TONE: Record<string, string> = {
  NEW: "border-red-200 bg-red-50 text-red-700",
  TRIAGE: "border-amber-200 bg-amber-50 text-amber-700",
  TRIAGED: "border-amber-200 bg-amber-50 text-amber-700",
  INVESTIGATING: "border-cyan-200 bg-cyan-50 text-cyan-700",
  CONTAINMENT: "border-orange-200 bg-orange-50 text-orange-700",
  ERADICATION: "border-orange-200 bg-orange-50 text-orange-700",
  RECOVERY: "border-emerald-200 bg-emerald-50 text-emerald-700",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
  REOPENED: "border-red-200 bg-red-50 text-red-700",
};

export const SEVERITY_TONE: Record<string, string> = {
  LOW: "border-emerald-200 bg-emerald-50 text-emerald-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
};

export const RULE_TYPE_LABEL: Record<string, string> = {
  DISTINCT_DEVICES: "Distinct devices",
  MULTI_COUNTRY: "Multi-country",
  BURST_SCANS: "Burst scans",
  TOO_MANY_REPORTS: "Too many reports",
};

export const ALERT_TYPE_LABEL: Record<string, string> = {
  MULTI_SCAN: "Multi-scan",
  GEO_DRIFT: "Geo drift",
  VELOCITY_SPIKE: "Velocity spike",
  STUCK_BATCH: "Stuck batch",
  AUTO_BLOCK_QR: "Auto-block QR",
  AUTO_BLOCK_BATCH: "Auto-block batch",
  POLICY_RULE: "Policy rule",
};

export const INCIDENT_TYPE_OPTIONS = [
  { value: "COUNTERFEIT_SUSPECTED", label: "Counterfeit suspected" },
  { value: "DUPLICATE_SCAN", label: "Duplicate scan" },
  { value: "TAMPERED_LABEL", label: "Tampered label" },
  { value: "WRONG_PRODUCT", label: "Wrong product" },
  { value: "OTHER", label: "Other" },
] as const;
