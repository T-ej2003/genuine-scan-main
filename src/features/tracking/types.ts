import { format } from "date-fns";
import type { LatestDecision } from "@/lib/verification-decision";

export type BatchSummaryRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  batchInventoryTotal: number;
  scopeCodeCount: number;
  scanEventCount: number;
  createdAt: string;
  counts?: Record<string, number>;
  latestDecision?: LatestDecision | null;
};

export type ScanLogRow = {
  id: string;
  code: string;
  status?: string | null;
  scanCount?: number | null;
  scannedAt: string;
  batchId?: string | null;
  device?: string | null;
  userAgent?: string | null;
  ipAddress?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
  locationName?: string | null;
  deviceLabel?: string | null;
  isFirstScan?: boolean | null;
  customerUserId?: string | null;
  ownershipId?: string | null;
  ownershipMatchMethod?: string | null;
  isTrustedOwnerContext?: boolean | null;
  latestDecision?: LatestDecision | null;
  licensee?: { id: string; name: string; prefix: string };
  qrCode?: { id: string; code: string; status: string };
};

export type TrackingEventSummary = {
  totalScanEvents: number;
  firstScanEvents: number;
  repeatScanEvents: number;
  blockedEvents: number;
  trustedOwnerEvents: number;
  externalEvents: number;
  namedLocationEvents: number;
  knownDeviceEvents: number;
};

export type TrackingFilterState = {
  code: string;
  batchQuery: string;
  status: string;
  firstScan: string;
  fromDate: string;
  toDate: string;
  licenseeId: string;
  outcome: string;
  riskBand: string;
  replacementStatus: string;
  customerTrustReviewState: string;
};

export const toCount = (counts: Record<string, number> | undefined, key: string) => counts?.[key] ?? 0;

const STATUS_TONE: Record<string, string> = {
  DORMANT: "border-slate-300 bg-slate-100 text-slate-700",
  ACTIVE: "border-slate-300 bg-slate-100 text-slate-700",
  ALLOCATED: "border-amber-200 bg-amber-50 text-amber-700",
  ACTIVATED: "border-amber-200 bg-amber-50 text-amber-700",
  PRINTED: "border-cyan-200 bg-cyan-50 text-cyan-700",
  REDEEMED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  SCANNED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  BLOCKED: "border-red-200 bg-red-50 text-red-700",
};

export const statusTone = (status?: string | null) =>
  STATUS_TONE[String(status || "").toUpperCase()] || "border-slate-300 bg-slate-100 text-slate-700";

export const formatLocation = (log: ScanLogRow) => {
  if (log.locationName) return log.locationName;
  if (typeof log.latitude === "number" && typeof log.longitude === "number") {
    const accuracyText =
      typeof log.accuracy === "number" && Number.isFinite(log.accuracy) ? ` (~${Math.round(log.accuracy)}m)` : "";
    return `GPS ${log.latitude.toFixed(3)}, ${log.longitude.toFixed(3)}${accuracyText}`;
  }
  return "Location unavailable";
};

export const describeScanContext = (log: ScanLogRow) => {
  if (log.isTrustedOwnerContext) {
    if (log.ownershipMatchMethod === "user") return "Trusted owner account";
    if (log.ownershipMatchMethod === "device_token") return "Trusted claimed device";
    return "Trusted owner context";
  }
  return "External / anonymous context";
};

export const formatScanTimestamp = (value?: string | null) => (value ? format(new Date(value), "PPp") : "—");
export const formatBatchCreatedDate = (value?: string | null) => (value ? format(new Date(value), "MMM d, yyyy") : "—");
