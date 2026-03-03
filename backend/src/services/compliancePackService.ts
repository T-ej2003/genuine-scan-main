import fs from "fs";
import path from "path";
import { createHash, createHmac, createPrivateKey, sign as cryptoSign } from "crypto";

import JSZip from "jszip";
import { UserRole } from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { generateComplianceReport } from "./governanceService";
import { logger } from "../utils/logger";

const ensureDir = (dir: string) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
};

const toBase64Url = (buf: Buffer) =>
  buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const stableStringify = (obj: any): string => {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map((v) => stableStringify(v)).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
};

const sha256Hex = (v: Buffer | string) => createHash("sha256").update(v).digest("hex");

const normalizePem = (value: string) => value.replace(/\\n/g, "\n").trim();

const parseIntEnv = (key: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const signPayload = (payload: string) => {
  const payloadHash = createHash("sha256").update(payload).digest();
  const privateKeyPem = process.env.QR_SIGN_PRIVATE_KEY;
  if (privateKeyPem) {
    const key = createPrivateKey(normalizePem(privateKeyPem));
    const signature = cryptoSign(null, payloadHash, key);
    return { algorithm: "ed25519", signature: toBase64Url(signature) };
  }

  const secret = String(process.env.QR_SIGN_HMAC_SECRET || process.env.JWT_SECRET || "genuine-scan-fallback-signing-key");
  const signature = createHmac("sha256", secret).update(payloadHash).digest();
  return { algorithm: "hmac-sha256", signature: toBase64Url(signature) };
};

const compliancePackDir = () => path.resolve(__dirname, "../../uploads/compliance-packs");

export const buildSignedComplianceEvidencePack = async (params: {
  actor: { userId: string; role: UserRole; licenseeId?: string | null };
  licenseeId?: string | null;
  from?: Date | null;
  to?: Date | null;
}) => {
  const report = await generateComplianceReport(params);
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
      "3) Verify signature with configured signing key",
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
  const signature = signPayload(integrityCanonical);

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
      signatureAlgorithm: signature.algorithm,
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
}) => {
  const job = await prisma.compliancePackJob.create({
    data: {
      triggerType: params.triggerType,
      status: "RUNNING",
      licenseeId: params.licenseeId || null,
      periodFrom: params.from || null,
      periodTo: params.to || null,
      startedByUserId: params.actor.userId,
      startedAt: new Date(),
    },
  });

  try {
    const pack = await buildSignedComplianceEvidencePack({
      actor: params.actor,
      licenseeId: params.licenseeId,
      from: params.from,
      to: params.to,
    });

    ensureDir(compliancePackDir());
    const storageKey = `${job.id}-${pack.fileName}`;
    const fullPath = path.join(compliancePackDir(), storageKey);
    fs.writeFileSync(fullPath, pack.buffer);

    const updated = await prisma.compliancePackJob.update({
      where: { id: job.id },
      data: {
        status: "COMPLETED",
        fileName: pack.fileName,
        storageKey,
        integrityHash: pack.metadata.integrityHash,
        signatureAlgorithm: pack.metadata.signatureAlgorithm,
        summary: {
          controls: pack.metadata.controls,
          generatedAt: pack.metadata.generatedAt,
        },
        finishedAt: new Date(),
      },
    });

    await createAuditLog({
      userId: params.actor.userId,
      licenseeId: params.licenseeId || undefined,
      action: "COMPLIANCE_PACK_GENERATED",
      entityType: "CompliancePackJob",
      entityId: updated.id,
      details: {
        triggerType: params.triggerType,
        fileName: updated.fileName,
        integrityHash: updated.integrityHash,
      },
    });

    return {
      job: updated,
      filePath: fullPath,
    };
  } catch (error) {
    const updated = await prisma.compliancePackJob.update({
      where: { id: job.id },
      data: {
        status: "FAILED",
        errorMessage: error instanceof Error ? error.message : String(error),
        finishedAt: new Date(),
      },
    });
    throw new Error(updated.errorMessage || "Compliance pack generation failed");
  }
};

export const listCompliancePackJobs = async (params: {
  licenseeId?: string | null;
  limit: number;
  offset: number;
}) => {
  const where: any = {};
  if (params.licenseeId) where.licenseeId = params.licenseeId;

  const [jobs, total] = await Promise.all([
    prisma.compliancePackJob.findMany({
      where,
      orderBy: { startedAt: "desc" },
      take: params.limit,
      skip: params.offset,
    }),
    prisma.compliancePackJob.count({ where }),
  ]);

  return { jobs, total };
};

export const loadCompliancePackJobBuffer = (storageKey: string) => {
  const fullPath = path.join(compliancePackDir(), storageKey);
  if (!fs.existsSync(fullPath)) return null;
  return fs.readFileSync(fullPath);
};

let schedulerStarted = false;
let schedulerTimer: NodeJS.Timeout | null = null;
let lastRunStamp = "";

export const startCompliancePackScheduler = () => {
  if (schedulerStarted) return;
  const enabled = ["1", "true", "yes", "on"].includes(
    String(process.env.COMPLIANCE_PACK_SCHEDULER_ENABLED || "false").trim().toLowerCase()
  );
  if (!enabled) return;

  const hourUtc = parseIntEnv("COMPLIANCE_PACK_SCHEDULER_HOUR_UTC", 2, 0, 23);
  const minuteUtc = parseIntEnv("COMPLIANCE_PACK_SCHEDULER_MINUTE_UTC", 0, 0, 59);

  schedulerStarted = true;
  schedulerTimer = setInterval(() => {
    void (async () => {
      const now = new Date();
      const stamp = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}-${hourUtc}-${minuteUtc}`;
      if (stamp === lastRunStamp) return;
      if (now.getUTCHours() !== hourUtc || now.getUTCMinutes() !== minuteUtc) return;

      const systemUser = await prisma.user.findFirst({
        where: {
          role: { in: ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"] as any },
          isActive: true,
        },
        select: { id: true, role: true, licenseeId: true },
      });
      if (!systemUser) return;

      const licensees = await prisma.licensee.findMany({
        where: { isActive: true },
        select: { id: true },
      });

      for (const licensee of licensees) {
        try {
          await runCompliancePackJob({
            triggerType: "SCHEDULED",
            actor: {
              userId: systemUser.id,
              role: systemUser.role as UserRole,
              licenseeId: systemUser.licenseeId,
            },
            licenseeId: licensee.id,
            from: new Date(Date.now() - 24 * 60 * 60 * 1000),
            to: new Date(),
          });
        } catch (error) {
          logger.warn("Scheduled compliance pack run failed", {
            licenseeId: licensee.id,
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
