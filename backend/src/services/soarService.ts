import { IncidentSeverity, IncidentStatus } from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { applyContainmentAction } from "./ir/incidentActionsService";

const parseIntEnv = (key: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const parseBool = (key: string, fallback: boolean) => {
  const raw = String(process.env[key] || "").trim().toLowerCase();
  if (!raw) return fallback;
  return ["1", "true", "yes", "on"].includes(raw);
};

const isEligibleSeverity = (severity: IncidentSeverity) =>
  severity === IncidentSeverity.HIGH || severity === IncidentSeverity.CRITICAL;

export const runIncidentAutoContainment = async (input: {
  incidentId: string;
  actorUserId?: string | null;
  ipAddress?: string | null;
  trigger: "PUBLIC_REPORT" | "IR_CREATE" | "INCIDENT_UPDATE";
}) => {
  if (!parseBool("SOAR_AUTO_CONTAINMENT_ENABLED", true)) {
    return { applied: [], skipped: ["SOAR auto-containment disabled"] };
  }

  const incident = await prisma.incident.findUnique({
    where: { id: input.incidentId },
    include: {
      qrCode: {
        select: {
          id: true,
          batchId: true,
          underInvestigationAt: true,
          batch: {
            select: {
              id: true,
              suspendedAt: true,
              licenseeId: true,
              licensee: { select: { id: true, suspendedAt: true } },
            },
          },
        },
      },
    },
  });

  if (!incident) return { applied: [], skipped: ["Incident not found"] };
  if (incident.status === IncidentStatus.REJECTED_SPAM) {
    return { applied: [], skipped: ["Rejected spam incident"] };
  }
  if (!isEligibleSeverity(incident.severity)) {
    return { applied: [], skipped: ["Severity below SOAR threshold"] };
  }

  const applied: Array<{ action: string; reason: string }> = [];
  const skipped: string[] = [];

  const batchId = incident.qrCode?.batchId || incident.qrCode?.batch?.id || null;
  const licenseeId = incident.licenseeId || incident.qrCode?.batch?.licenseeId || null;

  if (incident.qrCodeId && !incident.qrCode?.underInvestigationAt) {
    const reason = `SOAR auto-containment triggered by ${input.trigger} (${incident.severity})`;
    await applyContainmentAction({
      incidentId: incident.id,
      actorUserId: input.actorUserId || null,
      action: "FLAG_QR_UNDER_INVESTIGATION",
      reason,
      qrCodeId: incident.qrCodeId,
      batchId,
      licenseeId,
      ipAddress: input.ipAddress || null,
    });
    applied.push({ action: "FLAG_QR_UNDER_INVESTIGATION", reason });
  } else if (incident.qrCodeId) {
    skipped.push("QR already under investigation");
  }

  const batchThreshold = parseIntEnv("SOAR_BATCH_SUSPEND_THRESHOLD", 3, 2, 20);
  const orgThreshold = parseIntEnv("SOAR_ORG_SUSPEND_THRESHOLD", 10, 3, 100);
  const lookbackHours = parseIntEnv("SOAR_LOOKBACK_HOURS", 24, 1, 168);
  const lookbackSince = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

  if (batchId && incident.qrCode?.batch && !incident.qrCode.batch.suspendedAt) {
    const batchIncidentCount = await prisma.incident.count({
      where: {
        createdAt: { gte: lookbackSince },
        status: { not: IncidentStatus.REJECTED_SPAM },
        severity: { in: [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL] },
        qrCode: { batchId },
      },
    });

    if (batchIncidentCount >= batchThreshold) {
      const reason = `SOAR suspended batch after ${batchIncidentCount} high/critical incidents in ${lookbackHours}h`;
      await applyContainmentAction({
        incidentId: incident.id,
        actorUserId: input.actorUserId || null,
        action: "SUSPEND_BATCH",
        reason,
        batchId,
        licenseeId,
        ipAddress: input.ipAddress || null,
      });
      applied.push({ action: "SUSPEND_BATCH", reason });
    }
  }

  if (parseBool("SOAR_ALLOW_ORG_SUSPEND", false) && licenseeId && incident.qrCode?.batch?.licensee?.suspendedAt == null) {
    const orgIncidentCount = await prisma.incident.count({
      where: {
        createdAt: { gte: lookbackSince },
        status: { not: IncidentStatus.REJECTED_SPAM },
        severity: { in: [IncidentSeverity.CRITICAL] },
        licenseeId,
      },
    });

    if (orgIncidentCount >= orgThreshold) {
      const reason = `SOAR suspended organization after ${orgIncidentCount} critical incidents in ${lookbackHours}h`;
      await applyContainmentAction({
        incidentId: incident.id,
        actorUserId: input.actorUserId || null,
        action: "SUSPEND_ORG",
        reason,
        licenseeId,
        ipAddress: input.ipAddress || null,
      });
      applied.push({ action: "SUSPEND_ORG", reason });
    }
  }

  if (applied.length > 0) {
    await createAuditLog({
      userId: input.actorUserId || undefined,
      licenseeId: licenseeId || undefined,
      action: "SOAR_AUTO_CONTAINMENT_APPLIED",
      entityType: "Incident",
      entityId: incident.id,
      details: {
        trigger: input.trigger,
        severity: incident.severity,
        applied,
      },
      ipAddress: input.ipAddress || undefined,
    });
  }

  return { applied, skipped };
};
