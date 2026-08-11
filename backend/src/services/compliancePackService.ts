import fs from "fs";
import path from "path";
import { createHash, randomUUID } from "crypto";

import JSZip from "jszip";
import { UserRole } from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { ARTIFACT_PERSISTED_SIGNATURE_ALGORITHM, signArtifactPayload } from "./artifactSigningService";
import { downloadObjectBuffer, isObjectStorageConfigured, uploadObjectBuffer } from "./objectStorageService";
import {
  C03AccessError,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import {
  completeCompliancePackJobInTransaction,
  completeCompliancePackRebuildInTransaction,
  failCompliancePackJobInTransaction,
  listCompliancePackJobsInTransaction,
  loadCompliancePackJobInTransaction,
  startCompliancePackJobInTransaction,
} from "../rls-waves/session-c/c03/c03CompliancePackRepository";
import { withB03ScheduledContext } from "../rls-waves/session-b/b03/systemContext";
import {
  claimCompliancePackSlice,
  completeScheduledCompliancePackJob,
  failScheduledCompliancePackJob,
} from "../rls-waves/session-b/b03/repositoryFunctions";

const ensureDir = (dir: string) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
};

const stableStringify = (obj: any): string => {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map((v) => stableStringify(v)).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
};

const sha256Hex = (v: Buffer | string) => createHash("sha256").update(v).digest("hex");

const parseIntEnv = (key: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

type ComplianceSecurityContext = {
  databaseSessionCapability: string;
  requestId: string;
};

const complianceRoles = Object.values(UserRole);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const requireComplianceActorSecurity = (
  actor: { userId: string; role: UserRole; licenseeId?: string | null },
  security?: ComplianceSecurityContext
) => {
  const databaseSessionCapability = String(security?.databaseSessionCapability || "").trim();
  const requestId = String(security?.requestId || "").trim();
  if (!databaseSessionCapability || !requestId) {
    throw new C03AccessError("Canonical compliance actor context is required", 401);
  }
  return { databaseSessionCapability, requestId };
};

const requireComplianceSecurity = (
  actor: { userId: string; role: UserRole; licenseeId?: string | null },
  licenseeId: string | null | undefined,
  security?: ComplianceSecurityContext
) => {
  const verified = requireComplianceActorSecurity(actor, security);
  const boundedLicenseeId = String(licenseeId || actor.licenseeId || "").trim();
  if (!uuidPattern.test(boundedLicenseeId)) {
    throw new C03AccessError("A bounded compliance licensee scope is required", 400);
  }
  return { ...verified, licenseeId: boundedLicenseeId };
};

const compliancePackDir = () => path.resolve(__dirname, "../../uploads/compliance-packs");
const compliancePackObjectKey = (storageKey: string) => `compliance-packs/${path.basename(storageKey)}`;

const persistCompliancePackBuffer = async (storageKey: string, buffer: Buffer) => {
  if (isObjectStorageConfigured()) {
    const result = await uploadObjectBuffer({
      objectKey: compliancePackObjectKey(storageKey),
      body: buffer,
      contentType: "application/zip",
    });
    if (result.uploaded) {
      return { storageKey: result.key, filePath: null as string | null, storageMode: "object-storage" as const };
    }
  }

  ensureDir(compliancePackDir());
  const fullPath = path.join(compliancePackDir(), path.basename(storageKey));
  fs.writeFileSync(fullPath, buffer);
  return { storageKey: path.basename(storageKey), filePath: fullPath, storageMode: "local-disk" as const };
};

export const buildSignedComplianceEvidencePack = async (params: {
  licenseeId?: string | null;
  from?: Date | null;
  to?: Date | null;
  report?: Record<string, any>;
}) => {
  if (!params.report) throw new C03AccessError("Canonical compliance report snapshot is required", 500);
  const report = params.report;
  const generatedAt = new Date().toISOString();

  const controls = Array.isArray((report as any)?.controls) ? (report as any).controls : [];
  const evidenceMap = controls.map((control: any) => ({
    controlId: control.controlId,
    framework: control.framework,
    status: control.status,
    evidence: Array.isArray(control.evidenceRefs) ? control.evidenceRefs : [],
  }));

  const files: Record<string, string> = {
    "compliance-report.json": JSON.stringify(report, null, 2),
    "controls-map.json": JSON.stringify(controls, null, 2),
    "evidence-map.json": JSON.stringify(evidenceMap, null, 2),
    "README.txt": [
      "Compliance Evidence Pack",
      `Generated At: ${generatedAt}`,
      "",
      "Contents:",
      "- compliance-report.json: generated controls and metrics report",
      "- controls-map.json: framework control mapping (SOC 2 / ISO 27001)",
      "- evidence-map.json: control-to-evidence references",
      "- integrity.json: signed file hash envelope",
      "",
      "Verification:",
      "1) Hash each file with SHA-256 and compare with integrity.fileHashes",
      "2) Recompute integrityHash from canonical payload",
      "3) Verify signature with the artifact public-key registry",
    ].join("\n"),
  };

  const fileHashes = Object.entries(files).reduce((acc, [name, content]) => {
    acc[name] = sha256Hex(content);
    return acc;
  }, {} as Record<string, string>);

  const integrityPayload = {
    generatedAt,
    licenseeId: params.licenseeId || null,
    from: params.from?.toISOString() || null,
    to: params.to?.toISOString() || null,
    fileHashes,
  };
  const integrityCanonical = stableStringify(integrityPayload);
  const integrityHash = sha256Hex(integrityCanonical);
  const signature = signArtifactPayload(integrityCanonical);

  files["integrity.json"] = JSON.stringify(
    {
      ...integrityPayload,
      integrityHash,
      signature,
    },
    null,
    2
  );

  const zip = new JSZip();
  for (const [name, content] of Object.entries(files)) {
    zip.file(name, content);
  }

  const buffer = await zip.generateAsync({ type: "nodebuffer" });
  const fileName = `compliance-pack-${params.licenseeId || "global"}-${generatedAt.slice(0, 10)}.zip`;

  return {
    report,
    fileName,
    buffer,
    metadata: {
      generatedAt,
      integrityHash,
      signatureAlgorithm: ARTIFACT_PERSISTED_SIGNATURE_ALGORITHM,
      controls: controls.length,
    },
  };
};

export const runCompliancePackJob = async (params: {
  triggerType: "MANUAL" | "SCHEDULED";
  actor: { userId: string; role: UserRole; licenseeId?: string | null };
  licenseeId?: string | null;
  from?: Date | null;
  to?: Date | null;
  securityContext?: ComplianceSecurityContext;
}) => {
  if (params.triggerType === "SCHEDULED") {
    throw new C03AccessError("Restricted scheduled compliance worker boundary is required");
  }
  const security = requireComplianceSecurity(params.actor, params.licenseeId, params.securityContext);
  const started = await withC03ActorTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "compliance-pack-start",
      licenseeId: security.licenseeId,
      allowedRoles: complianceRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx, context) => startCompliancePackJobInTransaction(tx, context, {
      triggerType: params.triggerType,
      from: params.from,
      to: params.to,
    })
  );

  try {
    const pack = await buildSignedComplianceEvidencePack({
      licenseeId: security.licenseeId,
      from: params.from,
      to: params.to,
      report: started.report,
    });

    const storageKey = `${started.job.id}-${pack.fileName}`;
    const persisted = await persistCompliancePackBuffer(storageKey, pack.buffer);
    const updated = await withC03ResourceTransaction(
      {
        databaseSessionCapability: security.databaseSessionCapability,
        requestId: security.requestId,
        purpose: "compliance-pack-complete",
        resourceId: started.job.id,
        resourceType: "compliancePackJob",
        allowedRoles: complianceRoles,
        requiredAssurance: "mfa-verified",
      },
      (tx, context) => completeCompliancePackJobInTransaction<any>(tx, context, started.job.id, {
        fileName: pack.fileName,
        storageKey: persisted.storageKey,
        integrityHash: pack.metadata.integrityHash,
        signatureAlgorithm: pack.metadata.signatureAlgorithm,
        controls: pack.metadata.controls,
        generatedAt: pack.metadata.generatedAt,
        storageMode: persisted.storageMode,
      })
    );

    return {
      job: updated,
      filePath: persisted.filePath,
    };
  } catch (error) {
    await withC03ResourceTransaction(
      {
        databaseSessionCapability: security.databaseSessionCapability,
        requestId: security.requestId,
        purpose: "compliance-pack-fail",
        resourceId: started.job.id,
        resourceType: "compliancePackJob",
        allowedRoles: complianceRoles,
        requiredAssurance: "mfa-verified",
      },
      (tx, context) => failCompliancePackJobInTransaction(tx, context, started.job.id, "COMPLIANCE_PACK_BUILD_FAILED")
    ).catch(() => undefined);
    throw error;
  }
};

export const listCompliancePackJobs = async (params: {
  licenseeId?: string | null;
  limit: number;
  offset: number;
  actor?: { userId: string; role: UserRole; licenseeId?: string | null };
  securityContext?: ComplianceSecurityContext;
}) => {
  if (!params.actor) throw new C03AccessError("Canonical compliance actor context is required", 401);
  const security = requireComplianceSecurity(params.actor, params.licenseeId, params.securityContext);
  return withC03ActorTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "compliance-pack-list",
      licenseeId: security.licenseeId,
      allowedRoles: complianceRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx) => listCompliancePackJobsInTransaction(tx, {
      licenseeId: security.licenseeId,
      limit: params.limit,
      offset: params.offset,
    })
  );
};

export const loadCompliancePackJobBuffer = async (storageKey: string) => {
  const objectBuffer = await downloadObjectBuffer(storageKey);
  if (objectBuffer) return objectBuffer;

  const fullPath = path.join(compliancePackDir(), path.basename(storageKey));
  if (!fs.existsSync(fullPath)) return null;
  return fs.readFileSync(fullPath);
};

export const rebuildCompliancePackArtifactForJob = async (params: {
  jobId: string;
  actor: { userId: string; role: UserRole; licenseeId?: string | null };
  securityContext?: ComplianceSecurityContext;
}) => {
  const security = requireComplianceActorSecurity(params.actor, params.securityContext);
  const snapshot = await withC03ResourceTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "compliance-pack-rebuild-read",
      resourceId: params.jobId,
      resourceType: "compliancePackJob",
      allowedRoles: complianceRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx, context) => loadCompliancePackJobInTransaction<any>(tx, context, params.jobId)
  );
  const job = snapshot.job;

  const pack = await buildSignedComplianceEvidencePack({
    licenseeId: job.licenseeId || null,
    from: job.periodFrom ? new Date(job.periodFrom) : null,
    to: job.periodTo ? new Date(job.periodTo) : null,
    report: snapshot.report,
  });

  const storageKey = `${job.id}-rebuild-${Date.now()}-${pack.fileName}`;
  const persisted = await persistCompliancePackBuffer(storageKey, pack.buffer);

  const updated = await withC03ResourceTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "compliance-pack-rebuild-complete",
      resourceId: job.id,
      resourceType: "compliancePackJob",
      allowedRoles: complianceRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx, context) => completeCompliancePackRebuildInTransaction<any>(tx, context, job.id, {
      fileName: pack.fileName,
      storageKey: persisted.storageKey,
      integrityHash: pack.metadata.integrityHash,
      signatureAlgorithm: pack.metadata.signatureAlgorithm,
      controls: pack.metadata.controls,
      generatedAt: pack.metadata.generatedAt,
      storageMode: persisted.storageMode,
    })
  );

  return {
    job: updated,
    filePath: persisted.filePath,
  };
};

let schedulerStarted = false;
let schedulerTimer: NodeJS.Timeout | null = null;
let lastRunStamp = "";

export const startCompliancePackScheduler = () => {
  if (
    parseBool(process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS, false) ||
    !parseBool(process.env.RUN_COMPLIANCE_PACK_SCHEDULER, true)
  ) {
    return;
  }
  if (schedulerStarted) return;
  const enabled = ["1", "true", "yes", "on"].includes(
    String(process.env.COMPLIANCE_PACK_SCHEDULER_ENABLED || "false").trim().toLowerCase()
  );
  if (!enabled) return;

  const hourUtc = parseIntEnv("COMPLIANCE_PACK_SCHEDULER_HOUR_UTC", 2, 0, 23);
  const minuteUtc = parseIntEnv("COMPLIANCE_PACK_SCHEDULER_MINUTE_UTC", 0, 0, 59);
  const scheduleId = String(process.env.COMPLIANCE_PACK_SCHEDULE_ID || "daily-compliance-pack-v1").trim();
  const capability = String(process.env.MSCQR_SCHEDULED_JOB_CAPABILITY || "").trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(capability)) {
    logger.error("Compliance pack scheduler requires a database-verifiable scheduled capability");
    return;
  }

  schedulerStarted = true;
  schedulerTimer = setInterval(() => {
    void (async () => {
      const now = new Date();
      const stamp = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}-${hourUtc}-${minuteUtc}`;
      if (stamp === lastRunStamp) return;
      if (now.getUTCHours() !== hourUtc || now.getUTCMinutes() !== minuteUtc) return;

      const claims = await withB03ScheduledContext({
        capability,
        jobId: `schedule:${scheduleId}:${stamp}`,
        requestId: randomUUID(),
      }, (tx) => claimCompliancePackSlice(tx, { capability, scheduleId, dueAt: now, batchSize: 100 }));

      for (const claim of claims) {
        try {
          const pack = await buildSignedComplianceEvidencePack({
            licenseeId: claim.licenseeId,
            from: new Date(now.getTime() - 24 * 60 * 60 * 1000),
            to: now,
            report: claim.report,
          });
          const storageKey = `${claim.jobId}-${pack.fileName}`;
          const persisted = await persistCompliancePackBuffer(storageKey, pack.buffer);
          await withB03ScheduledContext({ capability, jobId: claim.jobId, requestId: claim.requestId,
            organizationId: claim.organizationId, licenseeId: claim.licenseeId }, (tx) =>
            completeScheduledCompliancePackJob(tx, { capability, scheduleId, requestId: claim.requestId,
              jobId: claim.jobId, result: { fileName: pack.fileName, storageKey: persisted.storageKey,
                integrityHash: pack.metadata.integrityHash, signatureAlgorithm: pack.metadata.signatureAlgorithm,
                controls: pack.metadata.controls, generatedAt: pack.metadata.generatedAt, storageMode: persisted.storageMode } })
          );
        } catch (error) {
          await withB03ScheduledContext({ capability, jobId: claim.jobId, requestId: randomUUID(),
            organizationId: claim.organizationId, licenseeId: claim.licenseeId }, (tx) =>
            failScheduledCompliancePackJob(tx, { capability, scheduleId, requestId: randomUUID(),
              jobId: claim.jobId, errorCode: "COMPLIANCE_PACK_BUILD_FAILED" })
          ).catch(() => undefined);
          logger.warn("Scheduled compliance pack run failed", {
            licenseeId: claim.licenseeId,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      lastRunStamp = stamp;
    })();
  }, 60_000);

  schedulerTimer.unref?.();
  logger.info("Compliance pack scheduler started", { hourUtc, minuteUtc });
};

export const stopCompliancePackScheduler = () => {
  if (schedulerTimer) clearInterval(schedulerTimer);
  schedulerTimer = null;
  schedulerStarted = false;
};
