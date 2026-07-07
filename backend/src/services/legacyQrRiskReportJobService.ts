import fs from "fs/promises";
import path from "path";

import {
  downloadObjectBuffer,
  isObjectStorageConfigured,
  uploadObjectBuffer,
} from "./objectStorageService";
import { getLegacyQrReport, serializeLegacyQrReportCsv } from "./legacyQrRotationService";
import { logger } from "../utils/logger";

type LegacyRiskReportJobOptions = {
  outputDir?: string | null;
  objectKeyPrefix?: string | null;
  now?: Date;
  uploadToObjectStorage?: boolean;
};

type PreviousLegacyReport = {
  totalLegacyCodes?: number | null;
};

const DEFAULT_OUTPUT_DIR = path.resolve(process.cwd(), "uploads/legacy-qr-risk-reports");
const DEFAULT_OBJECT_PREFIX = "legacy-qr-risk-reports";
const LATEST_FILE_NAME = "latest.json";
let schedulerTimer: NodeJS.Timeout | null = null;
let lastSchedulerRunKey: string | null = null;

const safeTimestamp = (date: Date) => date.toISOString().replace(/[:.]/g, "-");

const parsePreviousReport = (value: Buffer | string | null): PreviousLegacyReport | null => {
  if (!value) return null;
  try {
    const parsed = JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
    return parsed && typeof parsed === "object" ? (parsed as PreviousLegacyReport) : null;
  } catch {
    return null;
  }
};

export const buildLegacyQrRiskReportArtifacts = (report: Awaited<ReturnType<typeof getLegacyQrReport>>) => ({
  json: `${JSON.stringify(report, null, 2)}\n`,
  csv: `${serializeLegacyQrReportCsv(report)}\n`,
});

export const compareLegacyRiskTotals = (
  previous: PreviousLegacyReport | null,
  current: { totalLegacyCodes?: number | null }
) => {
  const previousTotal = Number(previous?.totalLegacyCodes ?? NaN);
  const currentTotal = Number(current.totalLegacyCodes ?? 0);
  return {
    previousTotal: Number.isFinite(previousTotal) ? previousTotal : null,
    currentTotal,
    increased: Number.isFinite(previousTotal) && currentTotal > previousTotal,
  };
};

export const buildLegacyQrRiskObjectKeys = (params: { prefix?: string | null; now: Date }) => {
  const prefix = String(params.prefix || DEFAULT_OBJECT_PREFIX).replace(/^\/+|\/+$/g, "") || DEFAULT_OBJECT_PREFIX;
  const stamp = safeTimestamp(params.now);
  return {
    json: `${prefix}/${stamp}.json`,
    csv: `${prefix}/${stamp}.csv`,
    latestJson: `${prefix}/${LATEST_FILE_NAME}`,
  };
};

const readLocalPreviousReport = async (outputDir: string) => {
  try {
    return parsePreviousReport(await fs.readFile(path.join(outputDir, LATEST_FILE_NAME)));
  } catch {
    return null;
  }
};

const readPreviousReport = async (params: {
  outputDir: string;
  objectKeyPrefix: string;
  uploadToObjectStorage: boolean;
  objectStorageConfigured: boolean;
}) => {
  if (params.uploadToObjectStorage && params.objectStorageConfigured) {
    const keys = buildLegacyQrRiskObjectKeys({ prefix: params.objectKeyPrefix, now: new Date() });
    return parsePreviousReport(await downloadObjectBuffer(keys.latestJson).catch(() => null));
  }
  return readLocalPreviousReport(params.outputDir);
};

export const runLegacyQrRiskReportJob = async (options: LegacyRiskReportJobOptions = {}) => {
  const now = options.now || new Date();
  const outputDir = path.resolve(String(options.outputDir || process.env.LEGACY_QR_REPORT_OUTPUT_DIR || DEFAULT_OUTPUT_DIR));
  const objectKeyPrefix = String(options.objectKeyPrefix || process.env.LEGACY_QR_REPORT_OBJECT_PREFIX || DEFAULT_OBJECT_PREFIX);
  const uploadToObjectStorage = options.uploadToObjectStorage !== false;
  const objectStorageConfigured = isObjectStorageConfigured();

  await fs.mkdir(outputDir, { recursive: true });
  const previous = await readPreviousReport({
    outputDir,
    objectKeyPrefix,
    uploadToObjectStorage,
    objectStorageConfigured,
  });

  const report = await getLegacyQrReport();
  const artifacts = buildLegacyQrRiskReportArtifacts(report);
  const stamp = safeTimestamp(now);
  const localJsonPath = path.join(outputDir, `${stamp}.json`);
  const localCsvPath = path.join(outputDir, `${stamp}.csv`);
  const latestJsonPath = path.join(outputDir, LATEST_FILE_NAME);

  await Promise.all([
    fs.writeFile(localJsonPath, artifacts.json, "utf8"),
    fs.writeFile(localCsvPath, artifacts.csv, "utf8"),
    fs.writeFile(latestJsonPath, artifacts.json, "utf8"),
  ]);

  const comparison = compareLegacyRiskTotals(previous, report);
  if (comparison.increased) {
    console.warn(
      `[legacy-qr-risk-report] totalLegacyCodes increased from ${comparison.previousTotal} to ${comparison.currentTotal}`
    );
  }

  const objectKeys = buildLegacyQrRiskObjectKeys({ prefix: objectKeyPrefix, now });
  const uploads =
    uploadToObjectStorage && objectStorageConfigured
      ? await Promise.all([
          uploadObjectBuffer({
            objectKey: objectKeys.json,
            body: Buffer.from(artifacts.json, "utf8"),
            contentType: "application/json; charset=utf-8",
          }),
          uploadObjectBuffer({
            objectKey: objectKeys.csv,
            body: Buffer.from(artifacts.csv, "utf8"),
            contentType: "text/csv; charset=utf-8",
          }),
          uploadObjectBuffer({
            objectKey: objectKeys.latestJson,
            body: Buffer.from(artifacts.json, "utf8"),
            contentType: "application/json; charset=utf-8",
          }),
        ])
      : [];

  return {
    report,
    localArtifacts: {
      jsonPath: localJsonPath,
      csvPath: localCsvPath,
      latestJsonPath,
    },
    objectStorage: {
      configured: objectStorageConfigured,
      attempted: uploadToObjectStorage && objectStorageConfigured,
      keys: objectKeys,
      uploads,
    },
    comparison,
  };
};

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseIntEnv = (name: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

export const startLegacyQrRiskReportScheduler = () => {
  if (
    parseBool(process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS, false) ||
    !parseBool(process.env.RUN_LEGACY_QR_RISK_REPORT_SCHEDULER, true)
  ) {
    return;
  }
  if (!parseBool(process.env.LEGACY_QR_REPORT_SCHEDULER_ENABLED, false)) return;
  if (schedulerTimer) return;

  const hourUtc = parseIntEnv("LEGACY_QR_REPORT_SCHEDULER_HOUR_UTC", 3, 0, 23);
  const minuteUtc = parseIntEnv("LEGACY_QR_REPORT_SCHEDULER_MINUTE_UTC", 15, 0, 59);

  schedulerTimer = setInterval(() => {
    const now = new Date();
    const runKey = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}-${hourUtc}-${minuteUtc}`;
    if (now.getUTCHours() !== hourUtc || now.getUTCMinutes() !== minuteUtc || lastSchedulerRunKey === runKey) return;
    lastSchedulerRunKey = runKey;
    void runLegacyQrRiskReportJob({ now }).catch((error) => {
      logger.error("Legacy QR risk report scheduler failed", { error: error?.message || error });
    });
  }, 60_000);
  schedulerTimer.unref?.();

  logger.info("Legacy QR risk report scheduler enabled", { hourUtc, minuteUtc });
};

export const stopLegacyQrRiskReportScheduler = () => {
  if (schedulerTimer) clearInterval(schedulerTimer);
  schedulerTimer = null;
};
