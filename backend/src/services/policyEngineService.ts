import { AlertSeverity, NotificationAudience, NotificationChannel, PolicyAlert, PolicyAlertType, QRStatus, SecurityPolicy } from "@prisma/client";
import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { evaluatePolicyRulesForScan } from "./ir/policyRuleEngineService";
import { createRoleNotifications } from "./notificationService";
import { isPrismaMissingTableError } from "../utils/prismaStorageGuard";
import { guardPublicIntegrityFallback } from "../utils/publicIntegrityGuard";

const ALERT_DEDUPE_WINDOW_MS = 15 * 60_000;

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

const severityFromScore = (score: number): AlertSeverity => {
  if (score >= 80) return AlertSeverity.CRITICAL;
  if (score >= 50) return AlertSeverity.HIGH;
  if (score >= 25) return AlertSeverity.MEDIUM;
  return AlertSeverity.LOW;
};

type CreatePolicyAlertInput = {
  licenseeId: string;
  alertType: PolicyAlertType;
  message: string;
  score: number;
  batchId?: string | null;
  qrCodeId?: string | null;
  manufacturerId?: string | null;
  details?: any;
  dedupeWindowMs?: number;
};

const createPolicyAlertIfFresh = async (input: CreatePolicyAlertInput): Promise<PolicyAlert | null> => {
  const windowMs = input.dedupeWindowMs ?? ALERT_DEDUPE_WINDOW_MS;
  const since = new Date(Date.now() - windowMs);

  const where: any = {
    licenseeId: input.licenseeId,
    alertType: input.alertType,
    createdAt: { gte: since },
    acknowledgedAt: null,
    batchId: input.batchId || null,
    qrCodeId: input.qrCodeId || null,
    manufacturerId: input.manufacturerId || null,
  };

  const existing = await prisma.policyAlert.findFirst({
    where,
    select: { id: true },
  });

  if (existing) return null;

  const created = await prisma.policyAlert.create({
    data: {
      licenseeId: input.licenseeId,
      alertType: input.alertType,
      severity: severityFromScore(input.score),
      message: input.message,
      score: input.score,
      batchId: input.batchId || null,
      qrCodeId: input.qrCodeId || null,
      manufacturerId: input.manufacturerId || null,
      details: input.details ?? null,
    },
  });

  await Promise.all([
    createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      type: "policy_alert_created",
      title: "New policy alert",
      body: created.message,
      incidentId: created.incidentId || null,
      data: {
        alertId: created.id,
        alertType: created.alertType,
        severity: created.severity,
        score: created.score,
        licenseeId: created.licenseeId,
        targetRoute: "/ir",
      },
      channels: [NotificationChannel.WEB],
    }),
    createRoleNotifications({
      audience: NotificationAudience.LICENSEE_ADMIN,
      licenseeId: created.licenseeId,
      type: "policy_alert_created",
      title: "Policy alert detected",
      body: created.message,
      incidentId: created.incidentId || null,
      data: {
        alertId: created.id,
        alertType: created.alertType,
        severity: created.severity,
        score: created.score,
        licenseeId: created.licenseeId,
        targetRoute: "/ir",
      },
      channels: [NotificationChannel.WEB],
    }),
  ]);

  return created;
};

export const getOrCreateSecurityPolicy = async (licenseeId: string): Promise<SecurityPolicy> => {
  return prisma.securityPolicy.upsert({
    where: { licenseeId },
    update: {},
    create: { licenseeId },
  });
};

export type PolicyScanInput = {
  qrCodeId: string;
  code: string;
  licenseeId: string;
  batchId?: string | null;
  manufacturerId?: string | null;
  scanCount: number;
  scannedAt?: Date;
  latitude?: number | null;
  longitude?: number | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  strictStorage?: boolean;
};

export type PolicyScanResult = {
  policy: Pick<
    SecurityPolicy,
    | "autoBlockEnabled"
    | "autoBlockBatchOnVelocity"
    | "multiScanThreshold"
    | "geoDriftThresholdKm"
    | "velocitySpikeThresholdPerMin"
    | "stuckBatchHours"
  >;
  triggered: {
    multiScan: boolean;
    geoDrift: boolean;
    velocitySpike: boolean;
  };
  autoBlockedQr: boolean;
  autoBlockedBatch: boolean;
  alerts: Array<{
    id: string;
    alertType: PolicyAlertType;
    severity: AlertSeverity;
    message: string;
    score: number;
  }>;
};

const buildNeutralPolicyResult = (): PolicyScanResult => ({
  policy: {
    autoBlockEnabled: true,
    autoBlockBatchOnVelocity: false,
    multiScanThreshold: 2,
    geoDriftThresholdKm: 300,
    velocitySpikeThresholdPerMin: 80,
    stuckBatchHours: 24,
  },
  triggered: {
    multiScan: false,
    geoDrift: false,
    velocitySpike: false,
  },
  autoBlockedQr: false,
  autoBlockedBatch: false,
  alerts: [],
});

export const evaluateScanAndEnforcePolicy = async (input: PolicyScanInput): Promise<PolicyScanResult> => {
  try {
    const now = input.scannedAt || new Date();
    const policy = await getOrCreateSecurityPolicy(input.licenseeId);
    const createdAlerts: PolicyAlert[] = [];

    let multiScan = false;
    let geoDrift = false;
    let velocitySpike = false;
    let geoDistance: number | null = null;
    let repeatIntervalMinutes: number | null = null;
    let rapidRepeatAcrossDistance = false;
    let velocityCount = 0;

    const multiThreshold = Math.max(2, policy.multiScanThreshold);
    if (input.scanCount >= multiThreshold) {
      multiScan = true;
      const score = Math.min(100, 45 + (input.scanCount - multiThreshold + 1) * 10);
      const alert = await createPolicyAlertIfFresh({
        licenseeId: input.licenseeId,
        alertType: PolicyAlertType.MULTI_SCAN,
        message: `QR ${input.code} exceeded multi-scan threshold (${input.scanCount}/${multiThreshold}).`,
        score,
        batchId: input.batchId || null,
        qrCodeId: input.qrCodeId,
        manufacturerId: input.manufacturerId || null,
        details: {
          threshold: multiThreshold,
          scanCount: input.scanCount,
          code: input.code,
        },
      });
      if (alert) createdAlerts.push(alert);
    }

    if (input.latitude != null && input.longitude != null) {
      const geoLogs = await prisma.qrScanLog.findMany({
        where: {
          qrCodeId: input.qrCodeId,
          latitude: { not: null },
          longitude: { not: null },
        },
        orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
        take: 2,
        select: { latitude: true, longitude: true, scannedAt: true },
      });

      if (geoLogs.length >= 2) {
        const current = geoLogs[0];
        const previous = geoLogs[1];
        if (
          current.latitude != null &&
          current.longitude != null &&
          previous.latitude != null &&
          previous.longitude != null
        ) {
          geoDistance = geoDistanceKm(
            current.latitude,
            current.longitude,
            previous.latitude,
            previous.longitude
          );
          const currentTs = current.scannedAt ? new Date(current.scannedAt).getTime() : NaN;
          const previousTs = previous.scannedAt ? new Date(previous.scannedAt).getTime() : NaN;
          if (Number.isFinite(currentTs) && Number.isFinite(previousTs)) {
            repeatIntervalMinutes = Math.abs(currentTs - previousTs) / 60_000;
          }
        }
      }

      const rapidRepeatMinutesThreshold = Number(process.env.POLICY_RAPID_REPEAT_MINUTES || "30");
      const rapidRepeatDistanceThresholdKm = Number(process.env.POLICY_RAPID_REPEAT_DISTANCE_KM || "80");
      if (
        repeatIntervalMinutes != null &&
        geoDistance != null &&
        repeatIntervalMinutes <= rapidRepeatMinutesThreshold &&
        geoDistance >= rapidRepeatDistanceThresholdKm
      ) {
        rapidRepeatAcrossDistance = true;
      }

      if (geoDistance != null && geoDistance >= policy.geoDriftThresholdKm) {
        geoDrift = true;
        const score = Math.min(
          100,
          50 + Math.round((geoDistance - policy.geoDriftThresholdKm) / Math.max(1, policy.geoDriftThresholdKm) * 40)
        );
        const alert = await createPolicyAlertIfFresh({
          licenseeId: input.licenseeId,
          alertType: PolicyAlertType.GEO_DRIFT,
          message: `QR ${input.code} showed geolocation drift of ${geoDistance.toFixed(
            1
          )} km (threshold ${policy.geoDriftThresholdKm} km).`,
          score,
          batchId: input.batchId || null,
          qrCodeId: input.qrCodeId,
          manufacturerId: input.manufacturerId || null,
          details: {
            thresholdKm: policy.geoDriftThresholdKm,
            driftKm: geoDistance,
            code: input.code,
          },
        });
        if (alert) createdAlerts.push(alert);
      }
    }

    if (input.batchId) {
      const windowStart = new Date(now.getTime() - 60_000);
      velocityCount = await prisma.qrScanLog.count({
        where: {
          batchId: input.batchId,
          scannedAt: { gte: windowStart },
        },
      });

      const velocityThreshold = Math.max(1, policy.velocitySpikeThresholdPerMin);
      if (velocityCount >= velocityThreshold) {
        velocitySpike = true;
        const score = Math.min(
          100,
          55 + Math.round((velocityCount - velocityThreshold + 1) / Math.max(1, velocityThreshold) * 35)
        );
        const alert = await createPolicyAlertIfFresh({
          licenseeId: input.licenseeId,
          alertType: PolicyAlertType.VELOCITY_SPIKE,
          message: `Batch scan velocity spike: ${velocityCount} scans/min (threshold ${velocityThreshold}/min).`,
          score,
          batchId: input.batchId,
          qrCodeId: input.qrCodeId,
          manufacturerId: input.manufacturerId || null,
          details: {
            thresholdPerMin: velocityThreshold,
            observedPerMin: velocityCount,
            windowStart: windowStart.toISOString(),
          },
        });
        if (alert) createdAlerts.push(alert);
      }
    }

    let autoBlockedQr = false;
    let autoBlockedBatch = false;

    const shouldAutoBlockByMultiScan =
      multiScan && input.scanCount >= multiThreshold + 1 && rapidRepeatAcrossDistance;

    if (policy.autoBlockEnabled && (shouldAutoBlockByMultiScan || geoDrift)) {
      const blockQr = await prisma.qRCode.updateMany({
        where: {
          id: input.qrCodeId,
          status: { not: QRStatus.BLOCKED },
        },
        data: {
          status: QRStatus.BLOCKED,
          blockedAt: now,
        },
      });

      if (blockQr.count > 0) {
        autoBlockedQr = true;

        const alert = await createPolicyAlertIfFresh({
          licenseeId: input.licenseeId,
          alertType: PolicyAlertType.AUTO_BLOCK_QR,
          message: `QR ${input.code} auto-blocked by policy engine.`,
          score: 95,
          batchId: input.batchId || null,
          qrCodeId: input.qrCodeId,
          manufacturerId: input.manufacturerId || null,
          details: {
            reasons: {
              multiScan,
              geoDrift,
              rapidRepeatAcrossDistance,
              repeatIntervalMinutes,
              geoDistance,
            },
          },
        });
        if (alert) createdAlerts.push(alert);

        await createAuditLog({
          licenseeId: input.licenseeId,
          action: "BLOCKED",
          entityType: "QRCode",
          entityId: input.qrCodeId,
          details: {
            code: input.code,
            batchId: input.batchId || null,
            manufacturerId: input.manufacturerId || null,
            reason: "Auto-blocked by policy engine",
            context: "POLICY_ENGINE",
            triggers: {
              multiScan,
              geoDrift,
              rapidRepeatAcrossDistance,
              repeatIntervalMinutes,
              geoDistance,
            },
          },
          ipAddress: input.ipAddress || undefined,
        });
      }
    }

    if (policy.autoBlockEnabled && policy.autoBlockBatchOnVelocity && velocitySpike && input.batchId) {
      const blockedBatchCodes = await prisma.qRCode.updateMany({
        where: {
          batchId: input.batchId,
          status: { not: QRStatus.BLOCKED },
        },
        data: {
          status: QRStatus.BLOCKED,
          blockedAt: now,
        },
      });

      if (blockedBatchCodes.count > 0) {
        autoBlockedBatch = true;

        const alert = await createPolicyAlertIfFresh({
          licenseeId: input.licenseeId,
          alertType: PolicyAlertType.AUTO_BLOCK_BATCH,
          message: `Batch ${input.batchId} auto-blocked due to scan velocity spike.`,
          score: 98,
          batchId: input.batchId,
          qrCodeId: input.qrCodeId,
          manufacturerId: input.manufacturerId || null,
          details: {
            blockedCodes: blockedBatchCodes.count,
            observedPerMin: velocityCount,
            thresholdPerMin: policy.velocitySpikeThresholdPerMin,
          },
        });
        if (alert) createdAlerts.push(alert);

        await createAuditLog({
          licenseeId: input.licenseeId,
          action: "BLOCKED",
          entityType: "Batch",
          entityId: input.batchId,
          details: {
            blockedCodes: blockedBatchCodes.count,
            reason: "Auto-blocked by policy engine (velocity spike)",
            context: "POLICY_ENGINE",
            thresholdPerMin: policy.velocitySpikeThresholdPerMin,
            observedPerMin: velocityCount,
          },
          ipAddress: input.ipAddress || undefined,
        });
      }
    }

    // Additional IR policy rules (superadmin-configurable)
    try {
      const ruleEval = await evaluatePolicyRulesForScan({
        licenseeId: input.licenseeId,
        qrCodeId: input.qrCodeId,
        code: input.code,
        batchId: input.batchId || null,
        manufacturerId: input.manufacturerId || null,
      });
      if (ruleEval.alerts.length > 0) createdAlerts.push(...ruleEval.alerts);
    } catch (e) {
      // Never fail scan verification because rule evaluation failed.
      console.error("evaluatePolicyRulesForScan failed:", e);
    }

    return {
      policy: {
        autoBlockEnabled: policy.autoBlockEnabled,
        autoBlockBatchOnVelocity: policy.autoBlockBatchOnVelocity,
        multiScanThreshold: policy.multiScanThreshold,
        geoDriftThresholdKm: policy.geoDriftThresholdKm,
        velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
        stuckBatchHours: policy.stuckBatchHours,
      },
      triggered: {
        multiScan,
        geoDrift,
        velocitySpike,
      },
      autoBlockedQr,
      autoBlockedBatch,
      alerts: createdAlerts.map((a) => ({
        id: a.id,
        alertType: a.alertType,
        severity: a.severity,
        message: a.message,
        score: a.score,
      })),
    };
  } catch (error) {
    if (isPrismaMissingTableError(error, ["securitypolicy", "policyalert", "qrscanlog"])) {
      guardPublicIntegrityFallback({
        strictStorage: input.strictStorage,
        warningKey: "scan-policy-storage",
        warningMessage: "[scan] Policy storage is unavailable. Continuing verification with a neutral policy result.",
        degradedMessage: "Verification is temporarily unavailable because policy enforcement storage is not ready.",
        degradedCode: "PUBLIC_POLICY_UNAVAILABLE",
      });
      return buildNeutralPolicyResult();
    }
    throw error;
  }
};
