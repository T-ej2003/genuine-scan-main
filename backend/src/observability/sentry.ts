import * as Sentry from "@sentry/node";

import { releaseMetadata } from "./release";

let sentryEnabled = false;

const toSampleRate = (raw: string | undefined) => {
  const value = Number(String(raw || "").trim());
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
};

export const initBackendMonitoring = () => {
  if (sentryEnabled) return true;

  const dsn = String(process.env.SENTRY_DSN_BACKEND || process.env.SENTRY_DSN || "").trim();
  if (!dsn) return false;

  Sentry.init({
    dsn,
    environment: releaseMetadata.environment,
    release: releaseMetadata.release,
    tracesSampleRate: toSampleRate(process.env.SENTRY_TRACES_SAMPLE_RATE),
    initialScope: {
      tags: {
        app_version: releaseMetadata.version,
        git_sha: releaseMetadata.shortGitSha,
      },
    },
  });

  sentryEnabled = true;
  return true;
};

export const captureBackendException = (
  error: unknown,
  context?: {
    requestId?: string;
    method?: string;
    path?: string;
    status?: number;
  }
) => {
  if (!sentryEnabled) return;

  if (!context) {
    Sentry.captureException(error);
    return;
  }

  Sentry.withScope((scope) => {
    if (context.requestId) scope.setTag("request_id", context.requestId);
    if (typeof context.status === "number") scope.setTag("http_status", String(context.status));
    if (context.method || context.path) {
      scope.setContext("http", {
        method: context.method || null,
        path: context.path || null,
        status: context.status ?? null,
      });
    }
    Sentry.captureException(error);
  });
};

export const flushBackendMonitoring = async (timeoutMs = 2000) => {
  if (!sentryEnabled) return;
  await Sentry.flush(timeoutMs);
};
