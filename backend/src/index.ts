import dotenv from "dotenv";
import path from "path";
import { createHash } from "crypto";
import packageJson from "../package.json";
import { createBackendApp } from "./app";
import prisma from "./config/database";
import { logger } from "./utils/logger";
import { startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } from "./services/siemOutboxService";
import { startAuditLogOutboxWorker, stopAuditLogOutboxWorker } from "./services/auditLogOutboxService";
import { startCompliancePackScheduler, stopCompliancePackScheduler } from "./services/compliancePackService";
import { resumePendingNetworkDirectJobs } from "./services/networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./services/networkIppPrintService";
import { startPrintConfirmationReconciler } from "./services/printConfirmationReconciler";
import { startAnalyticsRollupWorker } from "./services/analyticsRollupService";
import { releaseMetadata } from "./observability/release";
import { captureBackendException, flushBackendMonitoring, initBackendMonitoring } from "./observability/sentry";
import { hasConfiguredSecret } from "./utils/secretConfig";
import { getObjectStorageConfiguration } from "./services/objectStorageService";
import { isRedisConfigured } from "./services/redisService";
import {
  getQrSigningProfile,
  hasEd25519QrSigningKeys,
  hasManagedQrSignerBridgeRegistered,
  hasManagedQrSignerRefs,
  isManagedQrSignerRequested,
  validateQrSigningConfiguration,
} from "./services/qrTokenService";
import { bootstrapConfiguredSuperAdmin } from "./services/auth/superAdminBootstrapService";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const hasAnyConfiguredSecret = (...keys: string[]) => keys.some((key) => hasConfiguredSecret(key));
const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};
const asErrorRecord = (error: unknown) =>
  typeof error === "object" && error !== null
    ? (error as { code?: unknown; message?: unknown; safeCryptoMetadata?: unknown })
    : null;
const isKnownInsecureStorageCredential = (value: string) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return false;
  const fingerprint = createHash("sha256").update(normalized).digest("hex");
  return new Set([
    "98daf8223196e1b807f51d5c9f648dea2623dcb6e031adb5f05a6f2d6cbf0386",
    "72cbd1ce992c2cb9d9ade3d4f794dcce18e13004e0574dec0a8c81fdcebbd653",
    "ad9858116e63b0c5a4d7dc7f50f034c7247e56838dae22c1832712ffde48e694",
  ]).has(fingerprint);
};
const managedQrSigningRequested = isManagedQrSignerRequested();
const managedQrSigningRefsConfigured = hasManagedQrSignerRefs();
const managedQrSigningBridgeRegistered = hasManagedQrSignerBridgeRegistered();

const missingRequiredEnv = ["DATABASE_URL"].filter((k) => !process.env[k]);
if (!hasAnyConfiguredSecret("JWT_SECRET_CURRENT", "JWT_SECRET")) {
  missingRequiredEnv.push("JWT_SECRET_CURRENT or JWT_SECRET");
}
if (missingRequiredEnv.length > 0) {
  logger.error(`Missing required environment variables: ${missingRequiredEnv.join(", ")}`);
  process.exit(1);
}

const smtpConfigured = Boolean(
  (process.env.SMTP_USER || process.env.SMTP_USERNAME || process.env.EMAIL_USER || process.env.MAIL_USER) &&
    (process.env.SMTP_PASS || process.env.SMTP_PASSWORD || process.env.EMAIL_PASS || process.env.MAIL_PASS || process.env.MAIL_PASSWORD)
);
if (!smtpConfigured) {
  logger.warn(
    "⚠️ SMTP is not configured. Incident/customer emails will fail until SMTP_USER/SMTP_PASS (or EMAIL_/MAIL_ aliases) are set."
  );
}

const isPlaceholderValue = (value: string | undefined) => {
  const v = String(value || "").trim().toLowerCase();
  if (!v) return false;
  return (
    v.includes("your_rds_postgres_url_here") ||
    v.includes("your_strong_secret_here") ||
    v.includes("your_namecheap_private_email_password") ||
    v.includes("changeme") ||
    v.includes("replace_me")
  );
};

if (process.env.NODE_ENV === "production") {
  const placeholderEnv = [
    "DATABASE_URL",
    "JWT_SECRET",
    "SMTP_PASS",
    "SUPER_ADMIN_EMAIL",
    "PUBLIC_SCAN_WEB_BASE_URL",
    "PUBLIC_VERIFY_WEB_BASE_URL",
    "PUBLIC_ADMIN_WEB_BASE_URL",
  ].filter((key) => isPlaceholderValue(process.env[key]));

  if (placeholderEnv.length > 0) {
    logger.error(`Refusing to start: placeholder values detected in ${placeholderEnv.join(", ")}`);
    process.exit(1);
  }

  if (String(process.env.COOKIE_SECURE || "").trim().toLowerCase() !== "true") {
    logger.error("Refusing to start: COOKIE_SECURE must be 'true' in production.");
    process.exit(1);
  }

  if (parseBool(process.env.AUTH_LEGACY_TOKEN_RESPONSE_ENABLED, false)) {
    logger.error(
      "Refusing to start: AUTH_LEGACY_TOKEN_RESPONSE_ENABLED must remain false in production. The launch posture is cookie-backed auth only."
    );
    process.exit(1);
  }

  const insecurePublicUrls = [
    "PUBLIC_SCAN_WEB_BASE_URL",
    "PUBLIC_VERIFY_WEB_BASE_URL",
    "PUBLIC_ADMIN_WEB_BASE_URL",
    "WEB_APP_BASE_URL",
  ].filter((key) => {
    const value = String(process.env[key] || "").trim();
    return value && !value.toLowerCase().startsWith("https://");
  });

  if (insecurePublicUrls.length > 0) {
    logger.error(`Refusing to start: production public URLs must use HTTPS (${insecurePublicUrls.join(", ")})`);
    process.exit(1);
  }

  const hasQrEd25519 = hasAnyConfiguredSecret("QR_SIGN_PRIVATE_KEY") && hasAnyConfiguredSecret("QR_SIGN_PUBLIC_KEY");
  const hasQrHmac = hasAnyConfiguredSecret("QR_SIGN_HMAC_SECRET_CURRENT", "QR_SIGN_HMAC_SECRET");
  const enforceEd25519InProduction = parseBool(process.env.QR_SIGN_ENFORCE_ED25519_IN_PRODUCTION, true);

  if (managedQrSigningRequested && !managedQrSigningRefsConfigured) {
    logger.error(
      "Refusing to start: QR_SIGN_PROVIDER requests managed signing, but QR_SIGN_KMS_KEY_REF / QR_SIGN_KMS_VERIFY_KEY_REF are not configured."
    );
    process.exit(1);
  }

  if (managedQrSigningRequested && !managedQrSigningBridgeRegistered) {
    logger.error("Refusing to start: QR_SIGN_PROVIDER requests managed signing, but no managed signer bridge is registered.");
    process.exit(1);
  }

  const qrSigningConfigured = managedQrSigningRequested ? managedQrSigningRefsConfigured : hasQrEd25519 || hasQrHmac;

  const missingStrongSecurityEnv = [
    !qrSigningConfigured
      ? "QR signing configuration (managed bridge with QR_SIGN_KMS_* refs, or QR_SIGN_PRIVATE_KEY + QR_SIGN_PUBLIC_KEY, or QR_SIGN_HMAC_SECRET_CURRENT/QR_SIGN_HMAC_SECRET)"
      : "",
    !hasAnyConfiguredSecret("TOKEN_HASH_SECRET_CURRENT", "TOKEN_HASH_SECRET") ? "TOKEN_HASH_SECRET_CURRENT or TOKEN_HASH_SECRET" : "",
    !hasAnyConfiguredSecret("IP_HASH_SALT_CURRENT", "IP_HASH_SALT") ? "IP_HASH_SALT_CURRENT or IP_HASH_SALT" : "",
    !String(process.env.CUSTOMER_VERIFY_OTP_SECRET || "").trim() ? "CUSTOMER_VERIFY_OTP_SECRET" : "",
    !String(process.env.CUSTOMER_VERIFY_TOKEN_SECRET || "").trim() ? "CUSTOMER_VERIFY_TOKEN_SECRET" : "",
    !String(process.env.SCAN_FINGERPRINT_SECRET || "").trim() ? "SCAN_FINGERPRINT_SECRET" : "",
    !hasAnyConfiguredSecret("PRINTER_SSE_SIGN_SECRET_CURRENT", "PRINTER_SSE_SIGN_SECRET") ? "PRINTER_SSE_SIGN_SECRET_CURRENT or PRINTER_SSE_SIGN_SECRET" : "",
    !hasAnyConfiguredSecret("INCIDENT_HASH_SALT_CURRENT", "INCIDENT_HASH_SALT") ? "INCIDENT_HASH_SALT_CURRENT or INCIDENT_HASH_SALT" : "",
    !String(process.env.AUTH_MFA_ENCRYPTION_KEY || "").trim() ? "AUTH_MFA_ENCRYPTION_KEY" : "",
  ].filter(Boolean);

  if (missingStrongSecurityEnv.length > 0) {
    logger.error(
      `Refusing to start: production security hardening requires ${missingStrongSecurityEnv.join(", ")}`
    );
    process.exit(1);
  }

  if (enforceEd25519InProduction && !hasQrEd25519 && !managedQrSigningRequested) {
    logger.error(
      "Refusing to start: production QR signing must use Ed25519 when QR_SIGN_ENFORCE_ED25519_IN_PRODUCTION is enabled."
    );
    process.exit(1);
  }

  try {
    validateQrSigningConfiguration();
  } catch (error: unknown) {
    const errorRecord = asErrorRecord(error);
    logger.error("Refusing to start: QR signing configuration failed runtime validation.", {
      code: String(errorRecord?.code || "").trim() || null,
      cryptoMetadata: errorRecord?.safeCryptoMetadata || null,
    });
    process.exit(1);
  }

  if (hasQrEd25519 && !String(process.env.QR_SIGN_ACTIVE_KEY_VERSION || "").trim()) {
    logger.warn(
      "QR_SIGN_ACTIVE_KEY_VERSION is not set. MSCQR will derive a version from the public key, but explicit production key-version tracking is strongly recommended."
    );
  }

  if (!isRedisConfigured()) {
    logger.error("Refusing to start: production requires Redis coordination (REDIS_URL or REDIS_HOST/REDIS_PORT).");
    process.exit(1);
  }

  const objectStorageConfiguration = getObjectStorageConfiguration();
  if (!objectStorageConfiguration.configured) {
    logger.error(
      `Refusing to start: production requires object storage. ${objectStorageConfiguration.reason} Set OBJECT_STORAGE_BUCKET and OBJECT_STORAGE_REGION/AWS_REGION, then either rely on AWS default credentials/IAM task role with no static object storage credentials or provide OBJECT_STORAGE_ACCESS_KEY + OBJECT_STORAGE_SECRET_KEY for a separately approved custom S3-compatible endpoint. ASG web mode must use default credentials with no endpoint/static object-storage credentials.`
    );
    process.exit(1);
  }

  const objectStorageAccessKey = String(
    process.env.OBJECT_STORAGE_ACCESS_KEY || ""
  ).trim();
  const objectStorageSecretKey = String(
    process.env.OBJECT_STORAGE_SECRET_KEY || ""
  ).trim();
  if (
    objectStorageConfiguration.mode === "static-credentials" &&
    (isKnownInsecureStorageCredential(objectStorageAccessKey) || isKnownInsecureStorageCredential(objectStorageSecretKey))
  ) {
    logger.error(
      "Refusing to start: production object storage credentials are using known default/insecure values."
    );
    process.exit(1);
  }

  if (parseBool(process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED, false)) {
    logger.warn(
      "Production customer verify bearer compatibility is enabled. This should only be used as a documented emergency rollback path."
    );
  }
}

const usesLegacyFallback = (primaryKeys: string[], fallbackKeys: string[] = []) =>
  !primaryKeys.some((key) => hasConfiguredSecret(key)) && fallbackKeys.some((key) => hasConfiguredSecret(key));

const legacyFallbackWarnings = [
  {
    primaryKeys: ["QR_SIGN_HMAC_SECRET_CURRENT", "QR_SIGN_HMAC_SECRET"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: !hasConfiguredSecret("QR_SIGN_PRIVATE_KEY"),
    message:
      "QR signing HMAC is falling back to JWT_SECRET. Configure QR_SIGN_HMAC_SECRET_CURRENT so it can be rotated independently.",
  },
  {
    primaryKeys: ["PRINTER_SSE_SIGN_SECRET_CURRENT", "PRINTER_SSE_SIGN_SECRET"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: true,
    message:
      "Printer SSE signing is falling back to JWT_SECRET. Configure PRINTER_SSE_SIGN_SECRET_CURRENT to isolate that channel.",
  },
  {
    primaryKeys: ["INCIDENT_HASH_SALT_CURRENT", "INCIDENT_HASH_SALT"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: true,
    message:
      "Incident hashing is falling back to JWT_SECRET. Configure INCIDENT_HASH_SALT_CURRENT for independent rotation.",
  },
  {
    primaryKeys: ["QR_SIGN_ACTIVE_KEY_VERSION"],
    fallbackKeys: [],
    enabled: hasEd25519QrSigningKeys(),
    message:
      "QR signing is using Ed25519 without an explicit QR_SIGN_ACTIVE_KEY_VERSION. Configure it so verification evidence and rotations stay operationally traceable.",
  },
];

for (const warning of legacyFallbackWarnings) {
  if (warning.enabled && usesLegacyFallback(warning.primaryKeys, warning.fallbackKeys)) {
    logger.warn(warning.message);
  }
}

const app = createBackendApp();
const PORT = process.env.PORT || 4000;
const runBackgroundWorkers = parseBool(process.env.RUN_BACKGROUND_WORKERS, true);
const sentryEnabled = initBackendMonitoring();

if (sentryEnabled) {
  logger.info("Sentry monitoring enabled", {
    environment: releaseMetadata.environment,
    release: releaseMetadata.release,
  });
}

let server: ReturnType<typeof app.listen> | null = null;
let shuttingDown = false;
let stopPrintConfirmationReconcilerWorker: (() => void) | null = null;
let stopAnalyticsRollupWorker: (() => void) | null = null;

const startServer = async () => {
  const bootstrapResult = await bootstrapConfiguredSuperAdmin();
  if (bootstrapResult.status === "blocked") {
    logger.error("Refusing to start because super admin bootstrap is enabled but not safe to run", {
      reason: bootstrapResult.reason,
    });
    process.exit(1);
  }

  server = app.listen(PORT, () => {
    let qrSigningProfile: ReturnType<typeof getQrSigningProfile> | null = null;
    try {
      qrSigningProfile = getQrSigningProfile();
    } catch (error) {
      logger.warn("QR signing profile unavailable at startup", { error: (error as Error)?.message || error });
    }
    logger.info("Release metadata loaded", {
      environment: releaseMetadata.environment,
      release: releaseMetadata.release,
      gitSha: releaseMetadata.shortGitSha,
    });
    if (qrSigningProfile) {
      logger.info("QR signing profile ready", {
        mode: qrSigningProfile.mode,
        provider: qrSigningProfile.provider,
        keyVersion: qrSigningProfile.keyVersion,
        keyRef: qrSigningProfile.keyRef,
        legacyHmacFallback: Boolean(qrSigningProfile.legacyHmacFallback),
        managedSigningRequested: managedQrSigningRequested,
        managedSigningBridgeRegistered: managedQrSigningBridgeRegistered,
        kmsKeyRefConfigured: managedQrSigningRefsConfigured,
      });
    }
    logger.info(`🚀 Server running on http://localhost:${PORT}`);
    logger.info(`📚 API available at http://localhost:${PORT}/api`);
    logger.info(`🔍 Health check at http://localhost:${PORT}/health`);
    logger.info(`⏱️ Latency summary at http://localhost:${PORT}/health/latency`);
    if (runBackgroundWorkers) {
      startAuditLogOutboxWorker();
      startSecurityEventOutboxWorker();
      startCompliancePackScheduler();
      void resumePendingNetworkDirectJobs().catch((error) => {
        logger.error("Failed to resume pending network-direct jobs", { error: error?.message || error });
      });
      void resumePendingNetworkIppJobs().catch((error) => {
        logger.error("Failed to resume pending network IPP jobs", { error: error?.message || error });
      });
      stopPrintConfirmationReconcilerWorker = startPrintConfirmationReconciler();
      stopAnalyticsRollupWorker = startAnalyticsRollupWorker();
    } else {
      logger.info("Background workers disabled for this HTTP process");
    }
  });

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      logger.error(`Port ${PORT} is already in use. Stop the existing process or set a different PORT in backend/.env.`);
      process.exit(1);
    }
    logger.error("Server failed to start", { error: err?.message || err });
    process.exit(1);
  });
};

const shutdown = async (signal: string) => {
  if (shuttingDown) return;
  shuttingDown = true;

  logger.info(`Received ${signal}; shutting down gracefully...`);

  const forceExit = setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
  forceExit.unref?.();

  try {
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server!.close((err) => (err ? reject(err) : resolve()));
      });
    }
    stopSecurityEventOutboxWorker();
    stopAuditLogOutboxWorker();
    stopCompliancePackScheduler();
    stopPrintConfirmationReconcilerWorker?.();
    stopPrintConfirmationReconcilerWorker = null;
    stopAnalyticsRollupWorker?.();
    stopAnalyticsRollupWorker = null;
    await prisma.$disconnect();
    await flushBackendMonitoring();
    clearTimeout(forceExit);
    logger.info("Shutdown complete");
    process.exit(0);
  } catch (error: unknown) {
    const errorRecord = asErrorRecord(error);
    clearTimeout(forceExit);
    logger.error("Graceful shutdown failed", { error: errorRecord?.message || error });
    process.exit(1);
  }
};

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("unhandledRejection", (reason) => {
  captureBackendException(reason);
  logger.error("Unhandled promise rejection", { error: reason instanceof Error ? reason.message : String(reason) });
});

process.on("uncaughtException", (error) => {
  captureBackendException(error);
  logger.error("Uncaught exception", { error: error?.message || String(error) });
  void shutdown("uncaughtException");
});

void startServer().catch((error) => {
  captureBackendException(error);
  logger.error("Server startup failed", { error: error?.message || String(error) });
  process.exit(1);
});
