import fs from "fs";
import path from "path";
import JSZip from "jszip";

import { IncidentStatus, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { resolveUploadPath } from "../middleware/incidentUpload";
import { createAuditLog } from "./auditService";

type VerifyUxPolicy = {
  showTimelineCard: boolean;
  showRiskCards: boolean;
  allowOwnershipClaim: boolean;
  allowFraudReport: boolean;
  mobileCameraAssist: boolean;
};

const VERIFY_POLICY_DEFAULTS: VerifyUxPolicy = {
  showTimelineCard: true,
  showRiskCards: true,
  allowOwnershipClaim: true,
  allowFraudReport: true,
  mobileCameraAssist: true,
};

const VERIFY_POLICY_FLAG_MAP: Array<{ key: string; field: keyof VerifyUxPolicy }> = [
  { key: "verify_show_timeline_card", field: "showTimelineCard" },
  { key: "verify_show_risk_cards", field: "showRiskCards" },
  { key: "verify_allow_ownership_claim", field: "allowOwnershipClaim" },
  { key: "verify_allow_fraud_report", field: "allowFraudReport" },
  { key: "verify_mobile_camera_assist", field: "mobileCameraAssist" },
];

export const resolveVerifyUxPolicy = async (licenseeId?: string | null): Promise<VerifyUxPolicy> => {
  if (!licenseeId) return { ...VERIFY_POLICY_DEFAULTS };

  const flags = await prisma.tenantFeatureFlag.findMany({
    where: {
      licenseeId,
      key: { in: VERIFY_POLICY_FLAG_MAP.map((item) => item.key) },
    },
    select: {
      key: true,
      enabled: true,
      config: true,
    },
  });

  const byKey = new Map(flags.map((f) => [f.key, f]));
  const policy = { ...VERIFY_POLICY_DEFAULTS };

  for (const mapItem of VERIFY_POLICY_FLAG_MAP) {
    const flag = byKey.get(mapItem.key);
    if (!flag) continue;

    if (flag.config && typeof flag.config === "object" && (flag.config as any).force !== undefined) {
      policy[mapItem.field] = Boolean((flag.config as any).force);
      continue;
    }

    policy[mapItem.field] = Boolean(flag.enabled);
  }

  return policy;
};

export const listTenantFeatureFlags = async (licenseeId: string) => {
  return prisma.tenantFeatureFlag.findMany({
    where: { licenseeId },
    orderBy: [{ key: "asc" }],
  });
};

export const upsertTenantFeatureFlag = async (params: {
  licenseeId: string;
  key: string;
  enabled: boolean;
  config?: any;
  updatedByUserId?: string | null;
}) => {
  return prisma.tenantFeatureFlag.upsert({
    where: {
      licenseeId_key: {
        licenseeId: params.licenseeId,
        key: params.key,
      },
    },
    update: {
      enabled: params.enabled,
      config: params.config ?? null,
      updatedByUserId: params.updatedByUserId || null,
    },
    create: {
      licenseeId: params.licenseeId,
      key: params.key,
      enabled: params.enabled,
      config: params.config ?? null,
      updatedByUserId: params.updatedByUserId || null,
    },
  });
};

export const getOrCreateRetentionPolicy = async (licenseeId: string) => {
  return prisma.evidenceRetentionPolicy.upsert({
    where: { licenseeId },
    update: {},
    create: {
      licenseeId,
      retentionDays: Number(process.env.RETENTION_DAYS || "180"),
      purgeEnabled: false,
      exportBeforePurge: true,
      legalHoldTags: ["legal_hold", "compliance_hold"],
    },
  });
};

export const updateRetentionPolicy = async (params: {
  licenseeId: string;
  retentionDays?: number;
  purgeEnabled?: boolean;
  exportBeforePurge?: boolean;
  legalHoldTags?: string[];
  updatedByUserId?: string | null;
}) => {
  return prisma.evidenceRetentionPolicy.upsert({
    where: { licenseeId: params.licenseeId },
    update: {
      retentionDays: params.retentionDays,
      purgeEnabled: params.purgeEnabled,
      exportBeforePurge: params.exportBeforePurge,
      legalHoldTags: params.legalHoldTags,
      updatedByUserId: params.updatedByUserId || null,
    },
    create: {
      licenseeId: params.licenseeId,
      retentionDays: params.retentionDays ?? Number(process.env.RETENTION_DAYS || "180"),
      purgeEnabled: Boolean(params.purgeEnabled),
      exportBeforePurge: params.exportBeforePurge ?? true,
      legalHoldTags: params.legalHoldTags || ["legal_hold", "compliance_hold"],
      updatedByUserId: params.updatedByUserId || null,
    },
  });
};

const filterRetentionCandidates = (rows: Array<any>, legalHoldTags: string[]) => {
  const holdSet = new Set(legalHoldTags.map((t) => String(t || "").trim().toLowerCase()).filter(Boolean));
  return rows.filter((row) => {
    const tags = Array.isArray(row?.incident?.tags) ? row.incident.tags : [];
    const hasHold = tags.some((tag: string) => holdSet.has(String(tag || "").toLowerCase()));
    return !hasHold;
  });
};

export const runRetentionLifecycle = async (params: {
  licenseeId: string;
  startedByUserId?: string | null;
  mode: "PREVIEW" | "APPLY";
}) => {
  const policy = await getOrCreateRetentionPolicy(params.licenseeId);
  const cutoffAt = new Date(Date.now() - policy.retentionDays * 24 * 60 * 60 * 1000);

  const evidenceRows = await prisma.incidentEvidence.findMany({
    where: {
      incident: { licenseeId: params.licenseeId },
      createdAt: { lt: cutoffAt },
    },
    include: {
      incident: {
        select: { id: true, tags: true },
      },
    },
  });

  const eligible = filterRetentionCandidates(evidenceRows, policy.legalHoldTags || []);

  let purged = 0;
  let exported = 0;

  if (params.mode === "APPLY" && policy.purgeEnabled && eligible.length > 0) {
    if (policy.exportBeforePurge) {
      exported = eligible.length;
    }

    const ids = eligible.map((row) => row.id);

    await prisma.incidentEvidenceFingerprint.deleteMany({
      where: {
        incidentEvidenceId: { in: ids },
      },
    });

    await prisma.incidentEvidence.deleteMany({
      where: {
        id: { in: ids },
      },
    });

    purged = ids.length;

    for (const row of eligible) {
      const key = String(row.storageKey || "").trim();
      if (!key) continue;
      const full = resolveUploadPath(key);
      try {
        if (fs.existsSync(full)) fs.unlinkSync(full);
      } catch {
        // Best effort file cleanup.
      }
    }
  }

  const job = await prisma.evidenceRetentionJob.create({
    data: {
      licenseeId: params.licenseeId,
      status:
        params.mode === "APPLY" ? (policy.purgeEnabled ? "COMPLETED" : "FAILED") : "PREVIEW",
      mode: params.mode,
      cutoffAt,
      recordsEvaluated: evidenceRows.length,
      recordsPurged: purged,
      recordsExported: exported,
      startedByUserId: params.startedByUserId || null,
      finishedAt: new Date(),
      summary: {
        policy,
        eligibleCount: eligible.length,
        skippedDueToLegalHold: evidenceRows.length - eligible.length,
        purgeEnabled: policy.purgeEnabled,
      },
    },
  });

  return {
    job,
    policy,
    cutoffAt,
    evaluated: evidenceRows.length,
    eligible: eligible.length,
    purged,
    exported,
  };
};

const escapeCsv = (value: any) => {
  const raw = value == null ? "" : String(value);
  return /[",\n]/.test(raw) ? `"${raw.replace(/"/g, '""')}"` : raw;
};

export const buildIncidentEvidenceAuditBundle = async (incidentId: string) => {
  const incident = await prisma.incident.findUnique({
    where: { id: incidentId },
    include: {
      events: { orderBy: { createdAt: "asc" } },
      evidence: { orderBy: { createdAt: "asc" } },
      evidenceFingerprints: { orderBy: { createdAt: "asc" } },
      handoff: true,
      supportTicket: {
        include: {
          messages: { orderBy: { createdAt: "asc" } },
        },
      },
    },
  });

  if (!incident) throw new Error("Incident not found");

  const zip = new JSZip();
  const generatedAt = new Date().toISOString();

  zip.file(
    "incident.json",
    JSON.stringify(
      {
        generatedAt,
        incident,
      },
      null,
      2
    )
  );

  const evidenceCsv = [
    "evidenceId,storageKey,fileType,uploadedBy,createdAt,riskScore,sha256",
    ...incident.evidence.map((ev) => {
      const fp = incident.evidenceFingerprints.find((item) => item.incidentEvidenceId === ev.id);
      return [
        escapeCsv(ev.id),
        escapeCsv(ev.storageKey || ""),
        escapeCsv(ev.fileType || ""),
        escapeCsv(ev.uploadedBy),
        escapeCsv(ev.createdAt.toISOString()),
        escapeCsv(fp?.riskScore ?? ""),
        escapeCsv(fp?.sha256 || ""),
      ].join(",");
    }),
  ].join("\n");

  zip.file("evidence-summary.csv", evidenceCsv);
  zip.file("events.json", JSON.stringify(incident.events, null, 2));
  zip.file("fingerprints.json", JSON.stringify(incident.evidenceFingerprints, null, 2));

  const evidenceFolder = zip.folder("evidence-files");
  if (evidenceFolder) {
    for (const ev of incident.evidence) {
      const key = String(ev.storageKey || "").trim();
      if (!key) continue;
      const filePath = resolveUploadPath(key);
      if (!fs.existsSync(filePath)) continue;
      const buffer = fs.readFileSync(filePath);
      evidenceFolder.file(path.basename(key), buffer);
    }
  }

  const buffer = await zip.generateAsync({ type: "nodebuffer" });
  return {
    fileName: `incident-${incident.id}-evidence-audit.zip`,
    buffer,
    metadata: {
      incidentId: incident.id,
      generatedAt,
      evidenceCount: incident.evidence.length,
      eventsCount: incident.events.length,
      fingerprintCount: incident.evidenceFingerprints.length,
    },
  };
};

export const generateComplianceReport = async (params: {
  actor: {
    userId: string;
    role: UserRole;
    licenseeId?: string | null;
  };
  licenseeId?: string | null;
  from?: Date | null;
  to?: Date | null;
}) => {
  const scopedLicenseeId =
    params.actor.role === UserRole.SUPER_ADMIN || params.actor.role === UserRole.PLATFORM_SUPER_ADMIN
      ? params.licenseeId || null
      : params.actor.licenseeId || null;

  const range: any = {};
  if (params.from && Number.isFinite(params.from.getTime())) range.gte = params.from;
  if (params.to && Number.isFinite(params.to.getTime())) range.lte = params.to;

  const incidentWhere: any = {};
  const auditWhere: any = {};
  if (Object.keys(range).length > 0) {
    incidentWhere.createdAt = range;
    auditWhere.createdAt = range;
  }
  if (scopedLicenseeId) {
    incidentWhere.licenseeId = scopedLicenseeId;
    auditWhere.licenseeId = scopedLicenseeId;
  }

  const [
    totalIncidents,
    resolvedIncidents,
    breachedIncidents,
    totalFraudReports,
    totalAuditEvents,
    failedLoginAttempts,
    retentionPolicy,
    handoffSummary,
  ] = await Promise.all([
    prisma.incident.count({ where: incidentWhere }),
    prisma.incident.count({ where: { ...incidentWhere, status: { in: [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] } } }),
    prisma.incident.count({ where: { ...incidentWhere, slaDueAt: { lt: new Date() }, status: { notIn: [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] } } }),
    prisma.incident.count({ where: { ...incidentWhere, reportedBy: "CUSTOMER" } }),
    prisma.auditLog.count({ where: auditWhere }),
    prisma.auditLog.count({ where: { ...auditWhere, action: { contains: "LOGIN_FAILED" } } }),
    scopedLicenseeId ? getOrCreateRetentionPolicy(scopedLicenseeId) : null,
    prisma.incidentHandoff.groupBy({
      by: ["currentStage"],
      _count: { _all: true },
      where: scopedLicenseeId ? { incident: { licenseeId: scopedLicenseeId } } : undefined,
    }),
  ]);

  const handoff = handoffSummary.reduce((acc, row) => {
    acc[row.currentStage] = row._count._all;
    return acc;
  }, {} as Record<string, number>);

  const report = {
    generatedAt: new Date().toISOString(),
    appName: process.env.APP_NAME || "AUTHENTIC QR",
    scope: {
      licenseeId: scopedLicenseeId,
      from: params.from?.toISOString() || null,
      to: params.to?.toISOString() || null,
    },
    compliance: {
      ukGdpr: {
        statement:
          "Personal data is processed in accordance with UK GDPR and the Data Protection Act 2018.",
        contact: process.env.DPO_EMAIL || process.env.SUPER_ADMIN_EMAIL || "support@authenticqr.local",
      },
      securityAccess: {
        roleBasedAccess: ["Super Admin", "Licensee", "Manufacturer"],
        httpsEncrypted: true,
        passwordHandling: "Secure password hashing and OTP controls are enforced.",
        auditLogging: true,
      },
      incidentResponse: {
        workflow: ["report intake", "review", "containment", "documentation", "resolution"],
      },
      qrUsagePolicy: {
        uniqueTraceable: true,
        singleUseWhereApplicable: true,
        nonDuplicationRule: true,
      },
      auditRetentionDays: Number(process.env.RETENTION_DAYS || retentionPolicy?.retentionDays || 180),
      hosting: {
        provider: process.env.HOSTING_PROVIDER || "Cloud provider not set",
        disclaimer: "Service is provided on a best-effort basis with reasonable security controls.",
      },
    },
    metrics: {
      incidents: {
        total: totalIncidents,
        resolved: resolvedIncidents,
        slaBreachedOpen: breachedIncidents,
        handoff,
      },
      fraudReports: totalFraudReports,
      auditEvents: totalAuditEvents,
      failedLogins: failedLoginAttempts,
      retention: retentionPolicy
        ? {
            retentionDays: retentionPolicy.retentionDays,
            purgeEnabled: retentionPolicy.purgeEnabled,
            exportBeforePurge: retentionPolicy.exportBeforePurge,
            legalHoldTags: retentionPolicy.legalHoldTags,
          }
        : null,
    },
  };

  await createAuditLog({
    userId: params.actor.userId,
    licenseeId: scopedLicenseeId || undefined,
    action: "COMPLIANCE_REPORT_GENERATED",
    entityType: "ComplianceReport",
    entityId: scopedLicenseeId || "GLOBAL",
    details: {
      from: report.scope.from,
      to: report.scope.to,
      incidents: totalIncidents,
    },
  });

  return report;
};
