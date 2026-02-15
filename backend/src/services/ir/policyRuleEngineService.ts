import {
  AlertSeverity,
  IncidentActorType,
  IncidentEventType,
  IncidentPriority,
  IncidentSeverity,
  IncidentStatus,
  IncidentType,
  PolicyAlert,
  PolicyAlertType,
  PolicyRule,
  PolicyRuleType,
} from "@prisma/client";

import prisma from "../../config/database";
import { createAuditLog } from "../auditService";
import { computeSlaDueAt, recordIncidentEvent } from "../incidentService";

const ALERT_DEDUPE_WINDOW_MS = 15 * 60_000;

const clampInt = (value: unknown, fallback: number) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.floor(n);
};

const scoreFromRatio = (observed: number, threshold: number) => {
  const safeThreshold = Math.max(1, threshold);
  const ratio = observed / safeThreshold;
  if (!Number.isFinite(ratio) || ratio <= 0) return 0;
  // 1.0 => 60, 2.0 => 90, capped at 100
  const score = Math.round(Math.min(100, 30 + ratio * 30));
  return Math.max(0, score);
};

const incidentSeverityFromAlertSeverity = (severity: AlertSeverity): IncidentSeverity => {
  if (severity === AlertSeverity.CRITICAL) return IncidentSeverity.CRITICAL;
  if (severity === AlertSeverity.HIGH) return IncidentSeverity.HIGH;
  if (severity === AlertSeverity.MEDIUM) return IncidentSeverity.MEDIUM;
  return IncidentSeverity.LOW;
};

const incidentPriorityDefaultFromSeverity = (severity: IncidentSeverity): IncidentPriority => {
  if (severity === IncidentSeverity.CRITICAL) return IncidentPriority.P1;
  if (severity === IncidentSeverity.HIGH) return IncidentPriority.P2;
  if (severity === IncidentSeverity.MEDIUM) return IncidentPriority.P3;
  return IncidentPriority.P4;
};

const ruleIncidentType = (ruleType: PolicyRuleType): IncidentType => {
  if (ruleType === PolicyRuleType.TOO_MANY_REPORTS) return IncidentType.OTHER;
  return IncidentType.DUPLICATE_SCAN;
};

const buildRuleMessage = (rule: PolicyRule, observed: number) => {
  const window = Math.max(1, rule.windowMinutes);
  if (rule.ruleType === PolicyRuleType.DISTINCT_DEVICES) {
    return `Distinct devices exceeded threshold: ${observed}/${rule.threshold} within ${window} minutes.`;
  }
  if (rule.ruleType === PolicyRuleType.MULTI_COUNTRY) {
    return `Multiple countries detected: ${observed}/${rule.threshold} within ${window} minutes.`;
  }
  if (rule.ruleType === PolicyRuleType.BURST_SCANS) {
    return `Burst scans exceeded threshold: ${observed}/${rule.threshold} within ${window} minutes.`;
  }
  if (rule.ruleType === PolicyRuleType.TOO_MANY_REPORTS) {
    return `High incident volume detected: ${observed}/${rule.threshold} reports within ${window} minutes.`;
  }
  return `Policy rule triggered: ${rule.ruleType} (${observed}/${rule.threshold}).`;
};

const createRuleAlertIfFresh = async (input: {
  licenseeId: string;
  policyRuleId: string;
  message: string;
  severity: AlertSeverity;
  score: number;
  batchId?: string | null;
  qrCodeId?: string | null;
  manufacturerId?: string | null;
  details?: any;
  dedupeWindowMs?: number;
}): Promise<PolicyAlert | null> => {
  const windowMs = input.dedupeWindowMs ?? ALERT_DEDUPE_WINDOW_MS;
  const since = new Date(Date.now() - windowMs);

  const existing = await prisma.policyAlert.findFirst({
    where: {
      licenseeId: input.licenseeId,
      alertType: PolicyAlertType.POLICY_RULE,
      policyRuleId: input.policyRuleId,
      createdAt: { gte: since },
      acknowledgedAt: null,
      batchId: input.batchId || null,
      qrCodeId: input.qrCodeId || null,
      manufacturerId: input.manufacturerId || null,
    },
    select: { id: true },
  });
  if (existing) return null;

  return prisma.policyAlert.create({
    data: {
      licenseeId: input.licenseeId,
      alertType: PolicyAlertType.POLICY_RULE,
      severity: input.severity,
      message: input.message,
      score: input.score,
      policyRuleId: input.policyRuleId,
      batchId: input.batchId || null,
      qrCodeId: input.qrCodeId || null,
      manufacturerId: input.manufacturerId || null,
      details: input.details ?? null,
    },
  });
};

const resolveActiveRulesForLicensee = async (licenseeId: string) => {
  const licensee = await prisma.licensee.findUnique({
    where: { id: licenseeId },
    select: { orgId: true },
  });
  const orgId = licensee?.orgId || null;

  const whereOr: any[] = [{ licenseeId }];
  if (orgId) whereOr.push({ orgId });
  whereOr.push({ licenseeId: null, orgId: null });

  const rules = await prisma.policyRule.findMany({
    where: {
      isActive: true,
      OR: whereOr,
    },
    orderBy: [{ createdAt: "asc" }],
  });

  return { rules, orgId };
};

export const evaluatePolicyRulesForScan = async (input: {
  licenseeId: string;
  qrCodeId: string;
  code: string;
  batchId?: string | null;
  manufacturerId?: string | null;
}): Promise<{ alerts: PolicyAlert[]; incidents: string[] }> => {
  const now = new Date();
  const { rules } = await resolveActiveRulesForLicensee(input.licenseeId);

  const createdAlerts: PolicyAlert[] = [];
  const createdIncidentIds: string[] = [];

  for (const rule of rules) {
    if (rule.manufacturerId) {
      if (!input.manufacturerId || input.manufacturerId !== rule.manufacturerId) continue;
    }
    if (rule.ruleType === PolicyRuleType.TOO_MANY_REPORTS) continue; // evaluated on incident creation

    const windowMinutes = Math.max(1, clampInt(rule.windowMinutes, 60));
    const threshold = Math.max(1, clampInt(rule.threshold, 1));
    const since = new Date(now.getTime() - windowMinutes * 60_000);

    let observed = 0;
    let sample: any = null;

    if (rule.ruleType === PolicyRuleType.DISTINCT_DEVICES) {
      const groups = await prisma.qrScanLog.groupBy({
        by: ["device"],
        where: {
          qrCodeId: input.qrCodeId,
          scannedAt: { gte: since },
          device: { not: null },
        },
        _count: { _all: true },
      });
      observed = groups.length;
      sample = groups
        .map((g) => ({ device: g.device, count: g._count?._all ?? 0 }))
        .filter((g) => Boolean(g.device))
        .slice(0, 6);
    } else if (rule.ruleType === PolicyRuleType.MULTI_COUNTRY) {
      const groups = await prisma.qrScanLog.groupBy({
        by: ["locationCountry"],
        where: {
          qrCodeId: input.qrCodeId,
          scannedAt: { gte: since },
          locationCountry: { not: null },
        },
        _count: { _all: true },
      });
      observed = groups.length;
      sample = groups
        .map((g) => ({ country: g.locationCountry, count: g._count?._all ?? 0 }))
        .filter((g) => Boolean(g.country))
        .slice(0, 6);
    } else if (rule.ruleType === PolicyRuleType.BURST_SCANS) {
      observed = await prisma.qrScanLog.count({
        where: {
          qrCodeId: input.qrCodeId,
          scannedAt: { gte: since },
        },
      });
    } else {
      continue;
    }

    if (observed < threshold) continue;

    const message = buildRuleMessage(rule, observed);
    const score = scoreFromRatio(observed, threshold);

    const alert = await createRuleAlertIfFresh({
      licenseeId: input.licenseeId,
      policyRuleId: rule.id,
      message,
      severity: rule.severity,
      score,
      batchId: input.batchId || null,
      qrCodeId: input.qrCodeId,
      manufacturerId: input.manufacturerId || null,
      details: {
        rule: {
          id: rule.id,
          name: rule.name,
          ruleType: rule.ruleType,
          threshold,
          windowMinutes,
        },
        observed,
        sample,
        code: input.code,
      },
    });
    if (!alert) continue;

    createdAlerts.push(alert);

    await createAuditLog({
      licenseeId: input.licenseeId,
      action: "POLICY_RULE_TRIGGERED",
      entityType: "PolicyRule",
      entityId: rule.id,
      details: {
        alertId: alert.id,
        code: input.code,
        qrCodeId: input.qrCodeId,
        batchId: input.batchId || null,
        manufacturerId: input.manufacturerId || null,
        observed,
        threshold,
        windowMinutes,
      },
    });

    if (!rule.autoCreateIncident) continue;

    const incidentSeverity = rule.incidentSeverity || incidentSeverityFromAlertSeverity(rule.severity);
    const incidentPriority = rule.incidentPriority || incidentPriorityDefaultFromSeverity(incidentSeverity);
    const incidentType = ruleIncidentType(rule.ruleType);

    const incident = await prisma.incident.create({
      data: {
        qrCodeId: input.qrCodeId,
        qrCodeValue: input.code,
        licenseeId: input.licenseeId,
        reportedBy: "ADMIN",
        incidentType,
        severity: incidentSeverity,
        severityOverridden: true,
        priority: incidentPriority,
        description: message,
        photos: [],
        tags: ["policy_rule", String(rule.ruleType).toLowerCase()],
        status: IncidentStatus.NEW,
        slaDueAt: computeSlaDueAt(incidentSeverity),
      } as any,
    });

    await recordIncidentEvent({
      incidentId: incident.id,
      actorType: IncidentActorType.SYSTEM,
      actorUserId: null,
      eventType: IncidentEventType.CREATED,
      eventPayload: {
        source: "policy_rule",
        policyRuleId: rule.id,
        policyAlertId: alert.id,
        ruleType: rule.ruleType,
        observed,
        threshold,
        windowMinutes,
      },
    });

    await prisma.policyAlert.update({
      where: { id: alert.id },
      data: { incidentId: incident.id },
    });

    createdIncidentIds.push(incident.id);
  }

  return { alerts: createdAlerts, incidents: createdIncidentIds };
};

export const evaluatePolicyRulesForIncidentVolume = async (input: {
  incidentId: string;
  licenseeId?: string | null;
  manufacturerId?: string | null;
}): Promise<{ alerts: PolicyAlert[] }> => {
  const licenseeId = String(input.licenseeId || "").trim();
  if (!licenseeId) return { alerts: [] };

  const now = new Date();
  const { rules } = await resolveActiveRulesForLicensee(licenseeId);
  const createdAlerts: PolicyAlert[] = [];

  for (const rule of rules) {
    if (rule.ruleType !== PolicyRuleType.TOO_MANY_REPORTS) continue;
    if (rule.manufacturerId && input.manufacturerId && rule.manufacturerId !== input.manufacturerId) continue;

    const windowMinutes = Math.max(1, clampInt(rule.windowMinutes, 60));
    const threshold = Math.max(1, clampInt(rule.threshold, 1));
    const since = new Date(now.getTime() - windowMinutes * 60_000);

    const where: any = {
      licenseeId,
      createdAt: { gte: since },
      status: { not: IncidentStatus.REJECTED_SPAM },
    };

    const observed = await prisma.incident.count({ where });
    if (observed < threshold) continue;

    const message = buildRuleMessage(rule, observed);
    const score = scoreFromRatio(observed, threshold);

    const alert = await createRuleAlertIfFresh({
      licenseeId,
      policyRuleId: rule.id,
      message,
      severity: rule.severity,
      score,
      details: {
        rule: {
          id: rule.id,
          name: rule.name,
          ruleType: rule.ruleType,
          threshold,
          windowMinutes,
        },
        observed,
        incidentId: input.incidentId,
      },
    });
    if (!alert) continue;

    createdAlerts.push(alert);

    await prisma.policyAlert.update({
      where: { id: alert.id },
      data: { incidentId: input.incidentId },
    });

    await createAuditLog({
      licenseeId,
      action: "POLICY_RULE_TRIGGERED",
      entityType: "PolicyRule",
      entityId: rule.id,
      details: {
        alertId: alert.id,
        incidentId: input.incidentId,
        observed,
        threshold,
        windowMinutes,
      },
    });
  }

  return { alerts: createdAlerts };
};

