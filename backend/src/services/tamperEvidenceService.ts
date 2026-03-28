import fs from "fs/promises";
import path from "path";
import { createHash } from "crypto";

import prisma from "../config/database";
import { resolveUploadPath } from "../middleware/incidentUpload";
import { downloadObjectBuffer } from "./objectStorageService";

type EvidenceRecord = {
  id: string;
  incidentId: string;
  storageKey?: string | null;
  fileType?: string | null;
};

const EXPECTED_EXTENSIONS: Record<string, string[]> = {
  "image/jpeg": [".jpg", ".jpeg"],
  "image/jpg": [".jpg", ".jpeg"],
  "image/png": [".png"],
  "image/webp": [".webp"],
  "application/pdf": [".pdf"],
};

const fileSha256FromBytes = async (bytes: Buffer) => {
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  return { sha256, bytes };
};

const calculateRisk = (checks: {
  extensionMismatch: boolean;
  verySmallFile: boolean;
  duplicateInIncident: number;
  seenInOtherIncidents: number;
}) => {
  let risk = 0;
  if (checks.extensionMismatch) risk += 25;
  if (checks.verySmallFile) risk += 10;
  if (checks.duplicateInIncident > 0) risk += 25;
  if (checks.seenInOtherIncidents > 0) risk += Math.min(40, checks.seenInOtherIncidents * 10);
  return Math.min(100, risk);
};

export const runTamperEvidenceChecks = async (evidenceRows: EvidenceRecord[]) => {
  const findings: Array<{
    evidenceId: string;
    sha256?: string;
    riskScore: number;
    checks: Record<string, any>;
  }> = [];

  for (const evidence of evidenceRows) {
    const storageKey = String(evidence.storageKey || "").trim();
    if (!storageKey) continue;

    try {
      const resolvedPath = resolveUploadPath(storageKey);
      let bytes: Buffer;
      let fileSize: number;

      try {
        bytes = await fs.readFile(resolvedPath);
        const stat = await fs.stat(resolvedPath);
        fileSize = stat.size;
      } catch (localError: any) {
        if (localError?.code !== "ENOENT") throw localError;
        const objectBytes = await downloadObjectBuffer(storageKey);
        if (!objectBytes) throw localError;
        bytes = objectBytes;
        fileSize = objectBytes.length;
      }

      const { sha256 } = await fileSha256FromBytes(bytes);

      const mimeType = String(evidence.fileType || "application/octet-stream").toLowerCase();
      const ext = path.extname(storageKey).toLowerCase();
      const expected = EXPECTED_EXTENSIONS[mimeType] || [];

      const duplicateInIncident = await prisma.incidentEvidenceFingerprint.count({
        where: {
          incidentId: evidence.incidentId,
          sha256,
        },
      });

      const seenInOtherIncidents = await prisma.incidentEvidenceFingerprint.count({
        where: {
          sha256,
          incidentId: { not: evidence.incidentId },
        },
      });

      const checks = {
        extensionMismatch: expected.length > 0 ? !expected.includes(ext) : false,
        verySmallFile: fileSize < 1024,
        duplicateInIncident,
        seenInOtherIncidents,
        fileSizeBytes: fileSize,
        mimeType,
        ext,
      };

      const riskScore = calculateRisk(checks);

      await prisma.incidentEvidenceFingerprint.upsert({
        where: { incidentEvidenceId: evidence.id },
        update: {
          sha256,
          fileSize,
          mimeType,
          ext,
          duplicateCount: duplicateInIncident,
          seenInOtherIncidents,
          riskScore,
          checks,
        },
        create: {
          incidentEvidenceId: evidence.id,
          incidentId: evidence.incidentId,
          sha256,
          fileSize,
          mimeType,
          ext,
          duplicateCount: duplicateInIncident,
          seenInOtherIncidents,
          riskScore,
          checks,
        },
      });

      findings.push({
        evidenceId: evidence.id,
        sha256,
        riskScore,
        checks,
      });
    } catch (error: any) {
      findings.push({
        evidenceId: evidence.id,
        riskScore: 0,
        checks: {
          error: String(error?.message || "Unable to read file"),
        },
      });
    }
  }

  return findings;
};

export const summarizeTamperFindings = (findings: Array<{ riskScore: number; checks: Record<string, any> }>) => {
  if (!findings.length) {
    return {
      highestRisk: 0,
      hasWarnings: false,
      summary: "No attachment evidence provided for tamper analysis.",
    };
  }

  const highestRisk = findings.reduce((max, row) => Math.max(max, row.riskScore), 0);
  const suspicious = findings.filter((row) => row.riskScore >= 40);

  const hasCrossIncidentReuse = findings.some((row) => Number(row.checks?.seenInOtherIncidents || 0) > 0);
  const hasExtensionMismatch = findings.some((row) => Boolean(row.checks?.extensionMismatch));

  const parts: string[] = [];
  if (hasCrossIncidentReuse) parts.push("evidence hash reused in other incidents");
  if (hasExtensionMismatch) parts.push("file extension mismatch detected");
  if (!parts.length && highestRisk > 0) parts.push("minor evidence anomalies detected");

  return {
    highestRisk,
    hasWarnings: suspicious.length > 0 || hasCrossIncidentReuse || hasExtensionMismatch,
    summary: parts.length ? parts.join("; ") : "No tamper anomalies detected in attachment checks.",
  };
};
