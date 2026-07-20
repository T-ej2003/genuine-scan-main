import { Prisma, SecurityPolicy, UserRole, UserStatus } from "@prisma/client";
import { randomUUID } from "node:crypto";
import prisma from "../config/database";
import { CanonicalDbContext } from "../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../types";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { MANUFACTURER_ROLES, isLicenseeAdminRole, isPlatformRole } from "./manufacturerScopeService";
import { getOrCreateSecurityPolicy } from "./policyEngineService";
import { getBatchScanHistoryFallback } from "./scanLogReportingService";

const EARTH_RADIUS_KM = 6371;

const toRadians = (deg: number) => (deg * Math.PI) / 180;

const geoDistanceKm = (aLat: number, aLon: number, bLat: number, bLon: number) => {
  const dLat = toRadians(bLat - aLat);
  const dLon = toRadians(bLon - aLon);
  const lat1 = toRadians(aLat);
  const lat2 = toRadians(bLat);
  const h =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  return EARTH_RADIUS_KM * c;
};

const average = (values: number[]) => {
  if (!values.length) return null;
  const total = values.reduce((acc, v) => acc + v, 0);
  return Math.round((total / values.length) * 10) / 10;
};

const scoreToLevel = (score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" => {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
};

const defaultPolicy: Pick<
  SecurityPolicy,
  "multiScanThreshold" | "geoDriftThresholdKm" | "velocitySpikeThresholdPerMin" | "stuckBatchHours"
> = {
  multiScanThreshold: 2,
  geoDriftThresholdKm: 300,
  velocitySpikeThresholdPerMin: 80,
  stuckBatchHours: 24,
};

const loadPolicyForScope = async (licenseeId?: string) => {
  if (!licenseeId) return defaultPolicy;
  const policy = await getOrCreateSecurityPolicy(licenseeId);
  return {
    multiScanThreshold: policy.multiScanThreshold,
    geoDriftThresholdKm: policy.geoDriftThresholdKm,
    velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
    stuckBatchHours: policy.stuckBatchHours,
  };
};

type SlaStatus =
  | "PENDING_PRINT"
  | "PRINTED_PENDING_SCAN"
  | "SCANNED"
  | "STUCK_WAITING_PRINT"
  | "STUCK_WAITING_FIRST_SCAN";

export type BatchSlaRow = {
  batchId: string;
  name: string;
  licenseeId: string;
  manufacturerId: string | null;
  manufacturerName: string | null;
  createdAt: string;
  printedAt: string | null;
  firstScanAt: string | null;
  timeToPrintMinutes: number | null;
  timeToFirstScanMinutes: number | null;
  totalScans: number;
  status: SlaStatus;
  isStuck: boolean;
  stuckForHours: number | null;
};

export type BatchSlaAnalytics = {
  policy: { stuckBatchHours: number };
  summary: {
    totalBatches: number;
    printedBatches: number;
    scannedBatches: number;
    avgTimeToPrintMinutes: number | null;
    avgTimeToFirstScanMinutes: number | null;
    stuckBatches: number;
  };
  rows: BatchSlaRow[];
  stuckRows: BatchSlaRow[];
};

export const getBatchSlaAnalytics = async (opts: {
  licenseeId?: string;
  limit?: number;
  stuckBatchHours?: number;
}): Promise<BatchSlaAnalytics> => {
  const now = new Date();
  const limit = Math.max(1, Math.min(opts.limit ?? 200, 2000));
  const policy = await loadPolicyForScope(opts.licenseeId);
  const stuckHours = Math.max(1, opts.stuckBatchHours ?? policy.stuckBatchHours);

  const where: any = {};
  if (opts.licenseeId) where.licenseeId = opts.licenseeId;

  const batches = await prisma.batch.findMany({
    where,
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: limit,
    select: {
      id: true,
      name: true,
      licenseeId: true,
      manufacturerId: true,
      createdAt: true,
      printedAt: true,
      manufacturer: { select: { id: true, name: true } },
    },
  });

  if (!batches.length) {
    return {
      policy: { stuckBatchHours: stuckHours },
      summary: {
        totalBatches: 0,
        printedBatches: 0,
        scannedBatches: 0,
        avgTimeToPrintMinutes: null,
        avgTimeToFirstScanMinutes: null,
        stuckBatches: 0,
      },
      rows: [],
      stuckRows: [],
    };
  }

  const batchIds = batches.map((b) => b.id);

  const grouped = await prisma.scanMetricsHourlyRollup.groupBy({
    by: ["batchId"],
    where: { batchId: { in: batchIds } },
    _min: { firstScannedAt: true },
    _sum: { totalScanEvents: true },
  });

  const firstScanMap = new Map<string, Date>();
  const scanCountMap = new Map<string, number>();
  for (const g of grouped) {
    if (!g.batchId) continue;
    if (g._min.firstScannedAt) firstScanMap.set(g.batchId, g._min.firstScannedAt);
    scanCountMap.set(g.batchId, g._sum.totalScanEvents || 0);
  }

  const missingBatchIds = batchIds.filter((batchId) => !scanCountMap.has(batchId));
  if (missingBatchIds.length > 0) {
    const fallbackGrouped = await getBatchScanHistoryFallback(missingBatchIds);

    for (const group of fallbackGrouped) {
      if (!group.batchId) continue;
      if (group.firstScannedAt) firstScanMap.set(group.batchId, group.firstScannedAt);
      scanCountMap.set(group.batchId, Number(group.totalScanEvents || 0));
    }
  }

  const rows: BatchSlaRow[] = batches.map((b) => {
    const firstScanAt = firstScanMap.get(b.id) || null;
    const timeToPrintMinutes =
      b.printedAt != null ? Math.max(0, Math.round((b.printedAt.getTime() - b.createdAt.getTime()) / 60_000)) : null;
    const timeToFirstScanMinutes =
      b.printedAt != null && firstScanAt != null
        ? Math.max(0, Math.round((firstScanAt.getTime() - b.printedAt.getTime()) / 60_000))
        : null;

    let status: SlaStatus = "PENDING_PRINT";
    let stuckForHours: number | null = null;

    if (!b.printedAt) {
      const hours = (now.getTime() - b.createdAt.getTime()) / 3_600_000;
      if (hours >= stuckHours) {
        status = "STUCK_WAITING_PRINT";
        stuckForHours = Math.round(hours * 10) / 10;
      } else {
        status = "PENDING_PRINT";
      }
    } else if (!firstScanAt) {
      const hours = (now.getTime() - b.printedAt.getTime()) / 3_600_000;
      if (hours >= stuckHours) {
        status = "STUCK_WAITING_FIRST_SCAN";
        stuckForHours = Math.round(hours * 10) / 10;
      } else {
        status = "PRINTED_PENDING_SCAN";
      }
    } else {
      status = "SCANNED";
    }

    return {
      batchId: b.id,
      name: b.name,
      licenseeId: b.licenseeId,
      manufacturerId: b.manufacturerId || null,
      manufacturerName: b.manufacturer?.name || null,
      createdAt: b.createdAt.toISOString(),
      printedAt: b.printedAt ? b.printedAt.toISOString() : null,
      firstScanAt: firstScanAt ? firstScanAt.toISOString() : null,
      timeToPrintMinutes,
      timeToFirstScanMinutes,
      totalScans: scanCountMap.get(b.id) || 0,
      status,
      isStuck: status === "STUCK_WAITING_PRINT" || status === "STUCK_WAITING_FIRST_SCAN",
      stuckForHours,
    };
  });

  const stuckRows = rows.filter((r) => r.isStuck);
  const avgToPrint = average(rows.map((r) => r.timeToPrintMinutes).filter((v): v is number => v != null));
  const avgToFirstScan = average(
    rows.map((r) => r.timeToFirstScanMinutes).filter((v): v is number => v != null)
  );

  return {
    policy: { stuckBatchHours: stuckHours },
    summary: {
      totalBatches: rows.length,
      printedBatches: rows.filter((r) => r.printedAt != null).length,
      scannedBatches: rows.filter((r) => r.firstScanAt != null).length,
      avgTimeToPrintMinutes: avgToPrint,
      avgTimeToFirstScanMinutes: avgToFirstScan,
      stuckBatches: stuckRows.length,
    },
    rows,
    stuckRows,
  };
};

export type BatchRiskRow = {
  batchId: string;
  name: string;
  licenseeId: string;
  manufacturerId: string | null;
  manufacturerName: string | null;
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  multiScanAnomalies: number;
  geoDriftAnomalies: number;
  velocitySpikeEvents: number;
  openAlerts: number;
};

export type ManufacturerRiskRow = {
  manufacturerId: string;
  manufacturerName: string;
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  batches: number;
  multiScanAnomalies: number;
  geoDriftAnomalies: number;
  velocitySpikeEvents: number;
  openAlerts: number;
};

export type RiskAnalytics = {
  policy: {
    multiScanThreshold: number;
    geoDriftThresholdKm: number;
    velocitySpikeThresholdPerMin: number;
  };
  lookbackHours: number;
  summary: {
    analyzedBatches: number;
    analyzedManufacturers: number;
    highRiskBatches: number;
    highRiskManufacturers: number;
  };
  batchRisk: BatchRiskRow[];
  manufacturerRisk: ManufacturerRiskRow[];
};

export type RiskAnalyticsQuery = {
  licenseeId: string;
  lookbackHours: number;
  limit: number;
};

export class RiskAnalyticsAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const riskAnalyticsPurpose = "tenant-risk-analytics";
const riskAnalyticsWorkflowId = "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics";
const riskAnalyticsRoute = "GET /api/analytics/risk-scores";
export const RISK_ANALYTICS_MAX_CANDIDATE_BATCHES = 5_000;
export const RISK_ANALYTICS_MAX_DIMENSION_ROWS = 50_000;
export const RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS = 50_000;

export const buildRiskAnalyticsBoundary = (
  user: AuthenticatedSessionClaims,
  input: { requestedLicenseeId?: string; lookbackHours: number; limit: number },
  requestId: string
) => {
  const userId = String(user?.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  if (!userId || !normalizedRequestId || user?.sessionStage !== "ACTIVE") {
    throw new RiskAnalyticsAccessError("Authenticated actor context is required", 401);
  }
  const requestedLicenseeId = String(input.requestedLicenseeId || "").trim();
  if (!Number.isInteger(input.lookbackHours) || input.lookbackHours < 1 || input.lookbackHours > 24 * 30) {
    throw new RiskAnalyticsAccessError("Risk analytics date window is out of bounds", 400);
  }
  if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 200) {
    throw new RiskAnalyticsAccessError("Risk analytics page size is out of bounds", 400);
  }

  const platformActor = isPlatformRole(user.role);
  if (!platformActor && !isLicenseeAdminRole(user.role)) {
    throw new RiskAnalyticsAccessError("Risk analytics actor is not authorized");
  }
  if (platformActor) {
    if (user.licenseeId !== null || user.orgId !== null) {
      throw new RiskAnalyticsAccessError("Platform actor tenant scope must be empty");
    }
    const mfaVerifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
    if (
      user.authAssurance !== "ADMIN_MFA" ||
      !Number.isFinite(mfaVerifiedAt) ||
      Date.now() - mfaVerifiedAt > getAdminStepUpWindowMinutes() * 60_000
    ) {
      throw new RiskAnalyticsAccessError("Fresh administrator MFA is required");
    }
  } else if (!["PASSWORD", "ADMIN_MFA"].includes(user.authAssurance)) {
    throw new RiskAnalyticsAccessError("Risk analytics assurance is insufficient");
  }
  const licenseeId = platformActor ? requestedLicenseeId : String(user.licenseeId || "").trim();
  const organizationId = platformActor ? "" : String(user.orgId || "").trim();
  if (!uuid.test(licenseeId) || (!platformActor && !uuid.test(organizationId))) {
    throw new RiskAnalyticsAccessError("A valid tenant scope is required");
  }
  if (!platformActor && requestedLicenseeId && (!uuid.test(requestedLicenseeId) || requestedLicenseeId !== licenseeId)) {
    throw new RiskAnalyticsAccessError("Requested scope does not match the authenticated tenant");
  }

  return {
    context: {
      userId,
      role: String(user.role),
      organizationId: organizationId || null,
      licenseeId,
      manufacturerId: null,
      authAssurance: platformActor || user.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId: normalizedRequestId,
      purpose: riskAnalyticsPurpose,
    } satisfies CanonicalDbContext,
    query: { licenseeId, lookbackHours: input.lookbackHours, limit: input.limit } satisfies RiskAnalyticsQuery,
  };
};

const loadRiskPolicy = async (tx: Prisma.TransactionClient, licenseeId: string) => {
  const [policy] = await tx.$queryRaw<
    Array<Pick<SecurityPolicy, "multiScanThreshold" | "geoDriftThresholdKm" | "velocitySpikeThresholdPerMin">>
  >`
    SELECT "multiScanThreshold", "geoDriftThresholdKm", "velocitySpikeThresholdPerMin"
    FROM public."SecurityPolicy"
    WHERE "licenseeId" = ${licenseeId}
    LIMIT 1
  `;
  return policy || defaultPolicy;
};

const recordRiskAnalyticsRead = (
  tx: Prisma.TransactionClient,
  context: CanonicalDbContext,
  query: RiskAnalyticsQuery,
  result: { analyzedBatches: number; returnedBatches: number; analyzedManufacturers: number },
  timestamp: Date
) => {
  const details = {
    actorId: context.userId,
    role: context.role,
    assurance: context.authAssurance,
    requestId: context.requestId,
    purposeCode: context.purpose,
    organizationId: context.organizationId,
    licenseeId: context.licenseeId,
    workflowId: riskAnalyticsWorkflowId,
    route: riskAnalyticsRoute,
    outcome: "SUCCESS",
    lookbackHours: query.lookbackHours,
    limit: query.limit,
    analyzedBatchCount: result.analyzedBatches,
    returnedBatchCount: result.returnedBatches,
    analyzedManufacturerCount: result.analyzedManufacturers,
    timestamp: timestamp.toISOString(),
  };
  return tx.$executeRaw`
    INSERT INTO public."AuditLog"
      ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details")
    VALUES
      (${randomUUID()}, ${context.userId}, ${context.organizationId}, ${context.licenseeId},
       'RISK_ANALYTICS_READ', 'Licensee', ${context.licenseeId}, ${JSON.stringify(details)}::jsonb)
  `;
};

export const getRiskAnalytics = async (
  tx: Prisma.TransactionClient,
  query: RiskAnalyticsQuery,
  context: CanonicalDbContext,
  now = new Date()
): Promise<RiskAnalytics> => {
  const tenantActor = isLicenseeAdminRole(context.role as UserRole);
  const platformActor = isPlatformRole(context.role as UserRole);
  if (!uuid.test(query.licenseeId) || context.purpose !== riskAnalyticsPurpose) {
    throw new RiskAnalyticsAccessError("Risk analytics scope does not match canonical context");
  }
  if (!tenantActor && !platformActor) {
    throw new RiskAnalyticsAccessError("Risk analytics actor ceiling is invalid");
  }
  if (query.licenseeId !== context.licenseeId || tenantActor && !context.organizationId) {
    throw new RiskAnalyticsAccessError("Risk analytics scope does not match canonical context");
  }
  if (platformActor ? context.authAssurance !== "mfa-verified" : !["password-verified", "mfa-verified"].includes(context.authAssurance)) {
    throw new RiskAnalyticsAccessError("Risk analytics assurance is insufficient");
  }

  const actor = await tx.user.findUnique({
    where: { id: context.userId },
    select: {
      id: true,
      role: true,
      licenseeId: true,
      orgId: true,
      isActive: true,
      status: true,
      deletedAt: true,
      disabledAt: true,
    },
  });
  if (
    !actor ||
    actor.role !== context.role ||
    !actor.isActive ||
    actor.status !== UserStatus.ACTIVE ||
    actor.deletedAt !== null ||
    actor.disabledAt !== null ||
    tenantActor && (actor.licenseeId !== query.licenseeId || actor.orgId !== context.organizationId) ||
    platformActor && (actor.licenseeId !== null || actor.orgId !== null)
  ) {
    throw new RiskAnalyticsAccessError("Risk analytics actor or tenant authority is stale or inconsistent");
  }

  const tenant = await tx.licensee.findUnique({
    where: { id: query.licenseeId },
    select: { id: true, orgId: true, isActive: true, suspendedAt: true },
  });
  if (!tenant?.isActive || tenant.id !== query.licenseeId || tenant.suspendedAt || tenantActor && tenant.orgId !== context.organizationId) {
    throw new RiskAnalyticsAccessError("Tenant scope is inactive or inconsistent");
  }
  const organization = await tx.organization.findUnique({
    where: { id: tenant.orgId },
    select: { id: true, isActive: true },
  });
  if (!organization?.isActive || organization.id !== tenant.orgId) {
    throw new RiskAnalyticsAccessError("Tenant scope is inactive or inconsistent");
  }

  const scopedContext = platformActor ? { ...context, organizationId: tenant.orgId } : context;

  const limit = query.limit;
  const lookbackHours = query.lookbackHours;
  const policy = await loadRiskPolicy(tx, scopedContext.licenseeId!);
  const since = new Date(now.getTime() - lookbackHours * 3_600_000);

  const scanLogs = await tx.qrScanLog.findMany({
    where: {
      licenseeId: scopedContext.licenseeId!,
      batchId: { not: null },
      scannedAt: { gte: since, lte: now },
    },
    orderBy: [{ batchId: "asc" }, { qrCodeId: "asc" }, { scannedAt: "asc" }, { id: "asc" }],
    take: RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1,
    select: {
      id: true,
      licenseeId: true,
      qrCodeId: true,
      batchId: true,
      latitude: true,
      longitude: true,
      scannedAt: true,
      qrCode: { select: { id: true, licenseeId: true, batchId: true } },
      batch: { select: { id: true, licenseeId: true } },
    },
  });
  const scopedScanLogs = scanLogs.filter((row): row is typeof row & { batchId: string } => row.batchId !== null);
  const qrParents = new Map<string, string>();
  for (const row of scopedScanLogs) {
    const previousBatchId = qrParents.get(row.qrCodeId);
    if (
      row.licenseeId !== scopedContext.licenseeId ||
      !row.qrCode ||
      row.qrCode.id !== row.qrCodeId ||
      row.qrCode.licenseeId !== scopedContext.licenseeId ||
      row.qrCode.batchId !== row.batchId ||
      !row.batch ||
      row.batch.id !== row.batchId ||
      row.batch.licenseeId !== scopedContext.licenseeId ||
      (previousBatchId !== undefined && previousBatchId !== row.batchId)
    ) {
      throw new RiskAnalyticsAccessError("Risk analytics scan parentage is missing, foreign, or inconsistent", 422);
    }
    qrParents.set(row.qrCodeId, row.batchId);
  }
  if (scanLogs.length > RISK_ANALYTICS_MAX_DIMENSION_ROWS) {
    throw new RiskAnalyticsAccessError("Risk analytics scan dimension exceeds its bounded limit", 422);
  }

  const openAlertRows = await tx.policyAlert.findMany({
    where: {
      licenseeId: scopedContext.licenseeId!,
      batchId: { not: null },
      acknowledgedAt: null,
    },
    orderBy: [{ batchId: "asc" }, { id: "asc" }],
    take: RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS + 1,
    select: {
      id: true,
      licenseeId: true,
      batchId: true,
      qrCodeId: true,
      manufacturerId: true,
      incidentId: true,
      policyRuleId: true,
      acknowledgedAt: true,
    },
  });
  const scopedOpenAlertRows = openAlertRows.filter((row): row is typeof row & { batchId: string } => row.batchId !== null);
  if (scopedOpenAlertRows.some((row) => row.licenseeId !== scopedContext.licenseeId)) {
    throw new RiskAnalyticsAccessError("Risk analytics alert parentage is missing, foreign, or inconsistent", 422);
  }
  if (openAlertRows.length > RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS) {
    throw new RiskAnalyticsAccessError("Risk analytics open-alert set exceeds its bounded limit", 422);
  }

  const referencedBatchIds = [...new Set([
    ...scopedScanLogs.map((row) => row.batchId),
    ...scopedOpenAlertRows.map((row) => row.batchId),
  ].filter((id): id is string => Boolean(id)))].sort();
  if (referencedBatchIds.length > RISK_ANALYTICS_MAX_CANDIDATE_BATCHES) {
    throw new RiskAnalyticsAccessError("Risk analytics candidate batch set exceeds its bounded limit", 422);
  }
  const batches = await tx.batch.findMany({
    where: { licenseeId: scopedContext.licenseeId! },
    orderBy: { id: "asc" },
    take: RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1,
    select: {
      id: true,
      name: true,
      licenseeId: true,
      manufacturerId: true,
    },
  });
  const loadedBatchIds = new Set(batches.map((batch) => batch.id));
  if (batches.length > RISK_ANALYTICS_MAX_CANDIDATE_BATCHES) {
    throw new RiskAnalyticsAccessError("Risk analytics candidate batch set exceeds its bounded limit", 422);
  }
  if (
    loadedBatchIds.size !== batches.length ||
    batches.some((batch) => batch.licenseeId !== scopedContext.licenseeId) ||
    referencedBatchIds.some((id) => !loadedBatchIds.has(id))
  ) {
    throw new RiskAnalyticsAccessError("Risk analytics candidate parentage is missing, foreign, or inconsistent", 422);
  }

  const alertQrIds = [...new Set(scopedOpenAlertRows.map((row) => row.qrCodeId).filter((id): id is string => Boolean(id)))].sort();
  const alertManufacturerIds = [...new Set(scopedOpenAlertRows.map((row) => row.manufacturerId).filter((id): id is string => Boolean(id)))].sort();
  const alertIncidentIds = [...new Set(scopedOpenAlertRows.map((row) => row.incidentId).filter((id): id is string => Boolean(id)))].sort();
  const alertPolicyRuleIds = [...new Set(scopedOpenAlertRows.map((row) => row.policyRuleId).filter((id): id is string => Boolean(id)))].sort();
  const alertQrs = alertQrIds.length ? await tx.qRCode.findMany({
    where: { id: { in: alertQrIds } },
    orderBy: { id: "asc" },
    take: alertQrIds.length + 1,
    select: { id: true, licenseeId: true, batchId: true },
  }) : [];
  const alertManufacturers = alertManufacturerIds.length ? await tx.user.findMany({
    where: {
      id: { in: alertManufacturerIds },
      role: { in: MANUFACTURER_ROLES },
      isActive: true,
      status: UserStatus.ACTIVE,
      deletedAt: null,
      disabledAt: null,
    },
    orderBy: { id: "asc" },
    take: alertManufacturerIds.length + 1,
    select: { id: true },
  }) : [];
  const alertManufacturerLinks = alertManufacturerIds.length ? await tx.manufacturerLicenseeLink.findMany({
    where: { manufacturerId: { in: alertManufacturerIds }, licenseeId: scopedContext.licenseeId! },
    orderBy: [{ manufacturerId: "asc" }, { licenseeId: "asc" }],
    take: alertManufacturerIds.length + 1,
    select: { manufacturerId: true, licenseeId: true },
  }) : [];
  const alertIncidents = alertIncidentIds.length ? await tx.incident.findMany({
    where: { id: { in: alertIncidentIds } },
    orderBy: { id: "asc" },
    take: alertIncidentIds.length + 1,
    select: { id: true, licenseeId: true },
  }) : [];
  const alertPolicyRules = alertPolicyRuleIds.length ? await tx.policyRule.findMany({
    where: { id: { in: alertPolicyRuleIds } },
    orderBy: { id: "asc" },
    take: alertPolicyRuleIds.length + 1,
    select: { id: true, licenseeId: true, orgId: true, manufacturerId: true, isActive: true },
  }) : [];
  const alertQrMap = new Map(alertQrs.map((row) => [row.id, row]));
  const alertManufacturerSet = new Set(alertManufacturers.map((row) => row.id));
  const alertManufacturerLinkSet = new Set(alertManufacturerLinks.map((row) => row.manufacturerId));
  const alertIncidentMap = new Map(alertIncidents.map((row) => [row.id, row]));
  const alertPolicyRuleMap = new Map(alertPolicyRules.map((row) => [row.id, row]));
  if (
    alertQrs.length !== alertQrMap.size || alertQrMap.size !== alertQrIds.length ||
    alertManufacturers.length !== alertManufacturerSet.size || alertManufacturerSet.size !== alertManufacturerIds.length ||
    alertManufacturerLinks.length !== alertManufacturerLinkSet.size || alertManufacturerLinkSet.size !== alertManufacturerIds.length ||
    alertIncidents.length !== alertIncidentMap.size || alertIncidentMap.size !== alertIncidentIds.length ||
    alertPolicyRules.length !== alertPolicyRuleMap.size || alertPolicyRuleMap.size !== alertPolicyRuleIds.length
  ) {
    throw new RiskAnalyticsAccessError("Risk analytics alert parentage is missing, foreign, inactive, or inconsistent", 422);
  }
  const batchMap = new Map(batches.map((row) => [row.id, row]));
  for (const alert of scopedOpenAlertRows) {
    const batch = batchMap.get(alert.batchId);
    const qr = alert.qrCodeId ? alertQrMap.get(alert.qrCodeId) : null;
    const incident = alert.incidentId ? alertIncidentMap.get(alert.incidentId) : null;
    const rule = alert.policyRuleId ? alertPolicyRuleMap.get(alert.policyRuleId) : null;
    if (
      !batch || batch.licenseeId !== scopedContext.licenseeId ||
      (alert.qrCodeId && (!qr || qr.licenseeId !== scopedContext.licenseeId || qr.batchId !== alert.batchId)) ||
      (alert.manufacturerId && (!alertManufacturerSet.has(alert.manufacturerId) || !alertManufacturerLinkSet.has(alert.manufacturerId) || batch.manufacturerId !== alert.manufacturerId)) ||
      (alert.incidentId && (!incident || incident.licenseeId !== scopedContext.licenseeId)) ||
      (alert.policyRuleId && (!rule ||
        !rule.isActive ||
        (rule.licenseeId !== null && rule.licenseeId !== scopedContext.licenseeId) ||
        (rule.orgId !== null && rule.orgId !== scopedContext.organizationId) ||
        (rule.manufacturerId !== null && rule.manufacturerId !== alert.manufacturerId) ||
        (rule.licenseeId === null && rule.orgId === null && rule.manufacturerId === null)))
    ) {
      throw new RiskAnalyticsAccessError("Risk analytics alert parentage is missing, foreign, inactive, or inconsistent", 422);
    }
  }

  if (!batches.length) {
    const result = {
      policy: {
        multiScanThreshold: policy.multiScanThreshold,
        geoDriftThresholdKm: policy.geoDriftThresholdKm,
        velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
      },
      lookbackHours,
      summary: {
        analyzedBatches: 0,
        analyzedManufacturers: 0,
        highRiskBatches: 0,
        highRiskManufacturers: 0,
      },
      batchRisk: [],
      manufacturerRisk: [],
    };
    await recordRiskAnalyticsRead(tx, scopedContext, query, {
      analyzedBatches: 0,
      returnedBatches: 0,
      analyzedManufacturers: 0,
    }, now);
    return result;
  }

  const batchIds = batches.map((b) => b.id);

  const qrRows = await tx.qRCode.findMany({
    where: { licenseeId: scopedContext.licenseeId!, batchId: { in: batchIds } },
    orderBy: [{ batchId: "asc" }, { id: "asc" }],
    take: RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1,
    select: { batchId: true, scanCount: true },
  });
  if (qrRows.length > RISK_ANALYTICS_MAX_DIMENSION_ROWS) {
    throw new RiskAnalyticsAccessError("Risk analytics QR dimension exceeds its bounded limit", 422);
  }

  const multiScanByBatch = new Map<string, number>();
  for (const qr of qrRows) {
    if (!qr.batchId) continue;
    if (qr.scanCount >= policy.multiScanThreshold) {
      multiScanByBatch.set(qr.batchId, (multiScanByBatch.get(qr.batchId) || 0) + 1);
    }
  }

  const geoByQr = new Map<
    string,
    {
      batchId: string;
      firstLat: number;
      firstLon: number;
      lastLat: number;
      lastLon: number;
    }
  >();

  for (const log of scopedScanLogs) {
    if (log.latitude == null || log.longitude == null) continue;
    const existing = geoByQr.get(log.qrCodeId);
    if (!existing) {
      geoByQr.set(log.qrCodeId, {
        batchId: log.batchId,
        firstLat: log.latitude,
        firstLon: log.longitude,
        lastLat: log.latitude,
        lastLon: log.longitude,
      });
    } else {
      existing.lastLat = log.latitude;
      existing.lastLon = log.longitude;
    }
  }

  const geoDriftByBatch = new Map<string, number>();
  for (const item of geoByQr.values()) {
    const drift = geoDistanceKm(item.firstLat, item.firstLon, item.lastLat, item.lastLon);
    if (drift >= policy.geoDriftThresholdKm) {
      geoDriftByBatch.set(item.batchId, (geoDriftByBatch.get(item.batchId) || 0) + 1);
    }
  }

  const minuteBucketCounts = new Map<string, number>();
  for (const log of scopedScanLogs) {
    const d = new Date(log.scannedAt);
    const minute = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(
      d.getUTCDate()
    ).padStart(2, "0")}T${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(
      2,
      "0"
    )}`;
    const key = `${log.batchId}|${minute}`;
    minuteBucketCounts.set(key, (minuteBucketCounts.get(key) || 0) + 1);
  }

  const velocityByBatch = new Map<string, number>();
  for (const [key, count] of minuteBucketCounts.entries()) {
    if (count < policy.velocitySpikeThresholdPerMin) continue;
    const [batchId] = key.split("|");
    velocityByBatch.set(batchId, (velocityByBatch.get(batchId) || 0) + 1);
  }

  const openAlertsByBatch = new Map<string, number>();
  for (const row of scopedOpenAlertRows) {
    openAlertsByBatch.set(row.batchId, (openAlertsByBatch.get(row.batchId) || 0) + 1);
  }

  const manufacturerIds = [...new Set(batches.map((batch) => batch.manufacturerId).filter((id): id is string => Boolean(id)))];
  const manufacturers = manufacturerIds.length
    ? await tx.user.findMany({
        where: {
          id: { in: manufacturerIds },
          assignedBatches: { some: { id: { in: batchIds }, licenseeId: scopedContext.licenseeId! } },
        },
        orderBy: { id: "asc" },
        select: { id: true, name: true },
      })
    : [];
  const manufacturerNames = new Map(manufacturers.map((manufacturer) => [manufacturer.id, manufacturer.name]));

  const batchRiskAll: BatchRiskRow[] = batches.map((batch) => {
    const multi = multiScanByBatch.get(batch.id) || 0;
    const geo = geoDriftByBatch.get(batch.id) || 0;
    const velocity = velocityByBatch.get(batch.id) || 0;
    const openAlerts = openAlertsByBatch.get(batch.id) || 0;
    const score = Math.min(100, multi * 12 + geo * 22 + velocity * 28 + openAlerts * 5);
    return {
      batchId: batch.id,
      name: batch.name,
      licenseeId: batch.licenseeId,
      manufacturerId: batch.manufacturerId || null,
      manufacturerName: batch.manufacturerId ? manufacturerNames.get(batch.manufacturerId) || null : null,
      score,
      riskLevel: scoreToLevel(score),
      multiScanAnomalies: multi,
      geoDriftAnomalies: geo,
      velocitySpikeEvents: velocity,
      openAlerts,
    };
  });

  const manufacturerAgg = new Map<
    string,
    {
      manufacturerId: string;
      manufacturerName: string;
      batches: number;
      multiScanAnomalies: number;
      geoDriftAnomalies: number;
      velocitySpikeEvents: number;
      openAlerts: number;
    }
  >();

  for (const row of batchRiskAll) {
    if (!row.manufacturerId) continue;
    const existing = manufacturerAgg.get(row.manufacturerId);
    if (!existing) {
      manufacturerAgg.set(row.manufacturerId, {
        manufacturerId: row.manufacturerId,
        manufacturerName: row.manufacturerName || row.manufacturerId,
        batches: 1,
        multiScanAnomalies: row.multiScanAnomalies,
        geoDriftAnomalies: row.geoDriftAnomalies,
        velocitySpikeEvents: row.velocitySpikeEvents,
        openAlerts: row.openAlerts,
      });
      continue;
    }

    existing.batches += 1;
    existing.multiScanAnomalies += row.multiScanAnomalies;
    existing.geoDriftAnomalies += row.geoDriftAnomalies;
    existing.velocitySpikeEvents += row.velocitySpikeEvents;
    existing.openAlerts += row.openAlerts;
  }

  const manufacturerRiskAll: ManufacturerRiskRow[] = Array.from(manufacturerAgg.values()).map((m) => {
    const score = Math.min(
      100,
      m.multiScanAnomalies * 8 +
        m.geoDriftAnomalies * 16 +
        m.velocitySpikeEvents * 22 +
        m.openAlerts * 4 +
        m.batches * 2
    );
    return {
      manufacturerId: m.manufacturerId,
      manufacturerName: m.manufacturerName,
      score,
      riskLevel: scoreToLevel(score),
      batches: m.batches,
      multiScanAnomalies: m.multiScanAnomalies,
      geoDriftAnomalies: m.geoDriftAnomalies,
      velocitySpikeEvents: m.velocitySpikeEvents,
      openAlerts: m.openAlerts,
    };
  });

  const sortedBatchRisk = [...batchRiskAll].sort((a, b) => b.score - a.score || a.batchId.localeCompare(b.batchId));
  const sortedManufacturerRisk = [...manufacturerRiskAll].sort((a, b) => b.score - a.score || a.manufacturerId.localeCompare(b.manufacturerId));

  const result = {
    policy: {
      multiScanThreshold: policy.multiScanThreshold,
      geoDriftThresholdKm: policy.geoDriftThresholdKm,
      velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
    },
    lookbackHours,
    summary: {
      analyzedBatches: batchRiskAll.length,
      analyzedManufacturers: manufacturerRiskAll.length,
      highRiskBatches: batchRiskAll.filter((b) => b.score >= 65).length,
      highRiskManufacturers: manufacturerRiskAll.filter((m) => m.score >= 65).length,
    },
    batchRisk: sortedBatchRisk.slice(0, limit),
    manufacturerRisk: sortedManufacturerRisk.slice(0, limit),
  };
  await recordRiskAnalyticsRead(tx, scopedContext, query, {
    analyzedBatches: result.summary.analyzedBatches,
    returnedBatches: result.batchRisk.length,
    analyzedManufacturers: result.summary.analyzedManufacturers,
  }, now);
  return result;
};
