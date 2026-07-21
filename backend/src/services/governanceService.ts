import fs from "fs";
import path from "path";
import JSZip from "jszip";

import { Prisma, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { resolveUploadPath } from "../middleware/incidentUpload";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";
import {
  getOrCreateRetentionPolicyInTransaction,
  generateComplianceReportInTransaction,
  listTenantFeatureFlagsInTransaction,
  loadIncidentEvidenceAuditSnapshotInTransaction,
  RetentionLifecycleResult,
  runRetentionLifecycleInTransaction,
  updateRetentionPolicyInTransaction,
  upsertTenantFeatureFlagInTransaction,
} from "../rls-waves/session-c/c03/c03GovernanceRepository";

type VerifyUxPolicy = {
  showTimelineCard: boolean;
  showRiskCards: boolean;
  allowOwnershipClaim: boolean;
  allowFraudReport: boolean;
  mobileCameraAssist: boolean;
};

export type DuplicateRiskProfile = {
  tenantRiskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  productRiskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  anomalyWeight: number;
};

type ComplianceControlStatus = "EFFECTIVE" | "MONITOR" | "ATTENTION";

type ComplianceControl = {
  controlId: string;
  framework: "SOC2" | "ISO27001";
  title: string;
  status: ComplianceControlStatus;
  evidenceRefs: string[];
  note: string;
};

const VERIFY_POLICY_DEFAULTS: VerifyUxPolicy = {
  showTimelineCard: true,
  showRiskCards: true,
  allowOwnershipClaim: true,
  allowFraudReport: true,
  mobileCameraAssist: true,
};

const DUPLICATE_RISK_PROFILE_DEFAULTS: DuplicateRiskProfile = {
  tenantRiskLevel: "MEDIUM",
  productRiskLevel: "MEDIUM",
  anomalyWeight: 0.22,
};

const VERIFY_POLICY_FLAG_MAP: Array<{ key: string; field: keyof VerifyUxPolicy }> = [
  { key: "verify_show_timeline_card", field: "showTimelineCard" },
  { key: "verify_show_risk_cards", field: "showRiskCards" },
  { key: "verify_allow_ownership_claim", field: "allowOwnershipClaim" },
  { key: "verify_allow_fraud_report", field: "allowFraudReport" },
  { key: "verify_mobile_camera_assist", field: "mobileCameraAssist" },
];

const buildComplianceControls = (params: {
  reportGeneratedAt: string;
  resolvedIncidents: number;
  totalIncidents: number;
  breachedIncidents: number;
  failedLoginAttempts: number;
  totalAuditEvents: number;
  retentionDays: number;
}) => {
  const resolutionRatio =
    params.totalIncidents > 0 ? params.resolvedIncidents / Math.max(1, params.totalIncidents) : 1;
  const controls: ComplianceControl[] = [
    {
      controlId: "SOC2-CC7.2",
      framework: "SOC2",
      title: "Security event detection and response",
      status: params.breachedIncidents > 5 ? "ATTENTION" : "EFFECTIVE",
      evidenceRefs: [
        "metrics.incidents.slaBreachedOpen",
        "metrics.incidents.total",
        "metrics.incidents.resolved",
      ],
      note:
        params.breachedIncidents > 5
          ? "Open SLA breaches are elevated and require tighter response playbooks."
          : "Incident response SLAs are within expected operating range.",
    },
    {
      controlId: "SOC2-CC6.1",
      framework: "SOC2",
      title: "Logical access and authentication controls",
      status: params.failedLoginAttempts >= 20 ? "ATTENTION" : params.failedLoginAttempts >= 5 ? "MONITOR" : "EFFECTIVE",
      evidenceRefs: ["metrics.failedLogins", "compliance.securityAccess"],
      note:
        params.failedLoginAttempts >= 20
          ? "Failed login activity is high; investigate brute-force or credential-stuffing risk."
          : "Authentication telemetry is within expected range.",
    },
    {
      controlId: "ISO27001-A.5.23",
      framework: "ISO27001",
      title: "Information security for cloud services and logging",
      status: params.totalAuditEvents > 0 ? "EFFECTIVE" : "ATTENTION",
      evidenceRefs: ["metrics.auditEvents", "scope.licenseeId", "generatedAt"],
      note:
        params.totalAuditEvents > 0
          ? "Audit telemetry is being generated and retained."
          : "No audit activity observed for selected scope.",
    },
    {
      controlId: "ISO27001-A.8.10",
      framework: "ISO27001",
      title: "Information retention and deletion",
      status: params.retentionDays >= 180 ? "EFFECTIVE" : "MONITOR",
      evidenceRefs: ["compliance.auditRetentionDays", "metrics.retention"],
      note:
        params.retentionDays >= 180
          ? "Retention baseline meets long-horizon forensic needs."
          : "Retention window is shorter than enterprise-recommended baseline.",
    },
    {
      controlId: "SOC2-CC3.2",
      framework: "SOC2",
      title: "Monitoring control effectiveness",
      status: resolutionRatio >= 0.7 ? "EFFECTIVE" : "MONITOR",
      evidenceRefs: ["metrics.incidents.total", "metrics.incidents.resolved", "generatedAt"],
      note:
        resolutionRatio >= 0.7
          ? "Incident closure rate indicates controls are operating effectively."
          : "Resolution rate should improve; prioritize investigative throughput.",
    },
  ];

  const summary = controls.reduce(
    (acc, row) => {
      acc[row.status] = (acc[row.status] || 0) + 1;
      return acc;
    },
    { EFFECTIVE: 0, MONITOR: 0, ATTENTION: 0 } as Record<ComplianceControlStatus, number>
  );

  return {
    controls,
    summary,
    generatedAt: params.reportGeneratedAt,
  };
};

export const resolveVerifyUxPolicy = async (licenseeId?: string | null): Promise<VerifyUxPolicy> => {
  if (!licenseeId) return { ...VERIFY_POLICY_DEFAULTS };

  const flags = await prisma.tenantFeatureFlag
    .findMany({
      where: {
        licenseeId,
        key: { in: VERIFY_POLICY_FLAG_MAP.map((item) => item.key) },
      },
      select: {
        key: true,
        enabled: true,
        config: true,
      },
    })
    .catch((error) => {
      if (isPrismaMissingTableError(error, ["tenantfeatureflag"])) {
        warnStorageUnavailableOnce(
          "tenant-feature-flag-verify-policy",
          "[governance] TenantFeatureFlag table is unavailable. Using default verify UX policy."
        );
        return [];
      }
      throw error;
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

const normalizeRiskBand = (value: unknown, fallback: DuplicateRiskProfile["tenantRiskLevel"]) => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "LOW" || normalized === "MEDIUM" || normalized === "HIGH" || normalized === "CRITICAL") {
    return normalized;
  }
  return fallback;
};

export const resolveDuplicateRiskProfile = async (licenseeId?: string | null): Promise<DuplicateRiskProfile> => {
  const tenantId = String(licenseeId || "").trim();
  if (!tenantId) return { ...DUPLICATE_RISK_PROFILE_DEFAULTS };

  const flag = await prisma.tenantFeatureFlag
    .findUnique({
      where: {
        licenseeId_key: {
          licenseeId: tenantId,
          key: "verify_duplicate_risk_profile",
        },
      },
      select: {
        enabled: true,
        config: true,
      },
    })
    .catch((error) => {
      if (isPrismaMissingTableError(error, ["tenantfeatureflag"])) {
        warnStorageUnavailableOnce(
          "tenant-feature-flag-risk-profile",
          "[governance] TenantFeatureFlag table is unavailable. Using default duplicate risk profile."
        );
        return null;
      }
      throw error;
    });

  if (!flag) return { ...DUPLICATE_RISK_PROFILE_DEFAULTS };

  const config = flag.config && typeof flag.config === "object" ? (flag.config as Record<string, unknown>) : {};
  const tenantRiskLevel = normalizeRiskBand(
    config.tenantRiskLevel,
    flag.enabled ? DUPLICATE_RISK_PROFILE_DEFAULTS.tenantRiskLevel : "LOW"
  );
  const productRiskLevel = normalizeRiskBand(config.productRiskLevel, DUPLICATE_RISK_PROFILE_DEFAULTS.productRiskLevel);
  const anomalyWeightRaw = Number(config.anomalyWeight);
  const anomalyWeight = Number.isFinite(anomalyWeightRaw)
    ? Math.max(0.05, Math.min(0.8, anomalyWeightRaw))
    : DUPLICATE_RISK_PROFILE_DEFAULTS.anomalyWeight;

  return {
    tenantRiskLevel,
    productRiskLevel,
    anomalyWeight,
  };
};

type GovernanceTransaction = Pick<Prisma.TransactionClient, "$queryRaw" | "tenantFeatureFlag">;

const requireGovernanceTransaction = (db?: GovernanceTransaction): GovernanceTransaction => {
  if (!db) throw new Error("C03 canonical governance transaction is required");
  return db;
};

export const listTenantFeatureFlags = async (licenseeId: string, db?: GovernanceTransaction) =>
  listTenantFeatureFlagsInTransaction(requireGovernanceTransaction(db), licenseeId);

export const upsertTenantFeatureFlag = async (params: {
  licenseeId: string;
  key: string;
  enabled: boolean;
  config?: any;
  updatedByUserId?: string | null;
}, db?: GovernanceTransaction) =>
  upsertTenantFeatureFlagInTransaction<any>(requireGovernanceTransaction(db), {
    key: params.key,
    enabled: params.enabled,
    config: params.config,
  });

export const getOrCreateRetentionPolicy = async (_licenseeId: string, db?: GovernanceTransaction) =>
  getOrCreateRetentionPolicyInTransaction<any>(requireGovernanceTransaction(db));

export const updateRetentionPolicy = async (params: {
  licenseeId: string;
  retentionDays?: number;
  purgeEnabled?: boolean;
  exportBeforePurge?: boolean;
  legalHoldTags?: string[];
  updatedByUserId?: string | null;
}, db?: GovernanceTransaction) =>
  updateRetentionPolicyInTransaction<any>(requireGovernanceTransaction(db), {
    retentionDays: params.retentionDays,
    purgeEnabled: params.purgeEnabled,
    exportBeforePurge: params.exportBeforePurge,
    legalHoldTags: params.legalHoldTags,
  });

export const runRetentionLifecycle = async (params: {
  licenseeId: string;
  startedByUserId?: string | null;
  mode: "PREVIEW" | "APPLY";
  approvalId?: string | null;
}, db?: GovernanceTransaction): Promise<RetentionLifecycleResult> =>
  runRetentionLifecycleInTransaction(requireGovernanceTransaction(db), {
    mode: params.mode,
    approvalId: params.approvalId,
  });

export const deleteCommittedRetentionArtifacts = (storageKeys: readonly string[] = []) => {
  for (const key of storageKeys) {
    const normalized = String(key || "").trim();
    if (!normalized) continue;
    const full = resolveUploadPath(normalized);
    try {
      if (fs.existsSync(full)) fs.unlinkSync(full);
    } catch {
      // The database result is authoritative; storage cleanup is retried operationally.
    }
  }
};

const escapeCsv = (value: any) => {
  const raw = value == null ? "" : String(value);
  return /[",\n]/.test(raw) ? `"${raw.replace(/"/g, '""')}"` : raw;
};

export type IncidentEvidenceAuditSnapshot = {
  id: string;
  events: Array<Record<string, any>>;
  evidence: Array<Record<string, any> & { id: string; createdAt: string | Date }>;
  evidenceFingerprints: Array<Record<string, any> & { incidentEvidenceId: string }>;
  [key: string]: any;
};

export const loadIncidentEvidenceAuditSnapshot = async (
  incidentId: string,
  db?: GovernanceTransaction
) => loadIncidentEvidenceAuditSnapshotInTransaction<IncidentEvidenceAuditSnapshot>(
  requireGovernanceTransaction(db),
  incidentId
);

export const buildIncidentEvidenceAuditBundle = async (incident: IncidentEvidenceAuditSnapshot) => {

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
        escapeCsv(new Date(ev.createdAt).toISOString()),
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
}, db?: GovernanceTransaction) =>
  generateComplianceReportInTransaction<any>(requireGovernanceTransaction(db), {
    from: params.from,
    to: params.to,
  });
