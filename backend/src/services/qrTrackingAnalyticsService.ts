import { QRStatus } from "@prisma/client";
import type { InternalLatestDecision } from "./verificationDecisionReadService";
import { readScanAnalytics } from "../rls-waves/session-c/c01/qrSystemRepository";

export type TrackingAnalyticsScopeMode = "inventory" | "activity";

export type TrackingAnalyticsFilters = {
  databaseSessionCapability: string;
  requestId: string;
  licenseeId?: string;
  manufacturerId?: string;
  batchQuery?: string;
  code?: string;
  status?: QRStatus;
  firstScan?: boolean;
  from?: Date;
  to?: Date;
  limit: number;
  offset: number;
};

export type TrackingAnalyticsTotals = {
  total: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  created: number;
};

export type TrackingAnalyticsEventSummary = {
  totalScanEvents: number;
  firstScanEvents: number;
  repeatScanEvents: number;
  blockedEvents: number;
  trustedOwnerEvents: number;
  externalEvents: number;
  namedLocationEvents: number;
  knownDeviceEvents: number;
};

export type TrackingAnalyticsTrendPoint = {
  label: string;
  total: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  scanEvents: number;
};

export type TrackingAnalyticsBatchRow = {
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
  counts: Record<string, number>;
  latestDecision?: Pick<InternalLatestDecision, "outcome" | "riskBand" | "replacementStatus" | "customerTrustReviewState"> | null;
};

export const getQrTrackingAnalytics = async (filters: TrackingAnalyticsFilters) => {
  const { databaseSessionCapability, requestId, licenseeId, ...selectors } = filters;
  return readScanAnalytics({ capability: databaseSessionCapability, requestId, licenseeId, filters: selectors });
};
