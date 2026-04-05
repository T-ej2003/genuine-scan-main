import * as Sentry from "@sentry/react";

import { frontendRelease } from "@/lib/observability/release";
import { reportSupportRuntimeIssue } from "@/lib/support-diagnostics";

let initialized = false;

const toSampleRate = (raw: string | undefined) => {
  const value = Number(String(raw || "").trim());
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
};

const registerSupportRuntimeListeners = () => {
  if (typeof window === "undefined") return;

  window.addEventListener("error", (event) => {
    reportSupportRuntimeIssue({
      source: "runtime",
      message: event.message || "Unhandled window error",
      stack: event.error instanceof Error ? event.error.stack : undefined,
    });
  });

  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    const message =
      reason instanceof Error
        ? reason.message
        : typeof reason === "string"
          ? reason
          : "Unhandled promise rejection";

    reportSupportRuntimeIssue({
      source: "runtime",
      message,
      stack: reason instanceof Error ? reason.stack : undefined,
    });
  });
};

export const initFrontendMonitoring = () => {
  if (initialized) return;
  initialized = true;

  if (typeof window !== "undefined") {
    window.__MSCQR_RELEASE__ = frontendRelease;
  }

  registerSupportRuntimeListeners();

  const dsn = String(import.meta.env.VITE_SENTRY_DSN || "").trim();
  if (!dsn) return;

  Sentry.init({
    dsn,
    environment: frontendRelease.environment,
    release: frontendRelease.release,
    tracesSampleRate: toSampleRate(import.meta.env.VITE_SENTRY_SAMPLE_RATE),
    initialScope: {
      tags: {
        app_version: frontendRelease.version,
        git_sha: frontendRelease.shortGitSha,
      },
    },
  });
};
