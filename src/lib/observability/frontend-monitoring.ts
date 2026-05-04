import * as Sentry from "@sentry/react";

import { CONSENT_CHANGED_EVENT, hasConsent, type ConsentState } from "@/lib/consent";
import { frontendRelease } from "@/lib/observability/release";
import { reportSupportRuntimeIssue } from "@/lib/support-diagnostics";

let initialized = false;
let sentryInitialized = false;

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

const initSentryIfConsented = () => {
  if (sentryInitialized || !hasConsent("analytics")) return;

  const dsn = String(import.meta.env.VITE_SENTRY_DSN || "").trim();
  if (!dsn) return;

  const tracesSampleRate = toSampleRate(import.meta.env.VITE_SENTRY_SAMPLE_RATE);

  Sentry.init({
    dsn,
    environment: frontendRelease.environment,
    release: frontendRelease.release,
    tracesSampleRate,
    tracesSampler: () => (hasConsent("analytics") ? tracesSampleRate : 0),
    beforeSend: (event) => (hasConsent("analytics") ? event : null),
    beforeSendTransaction: (event) => (hasConsent("analytics") ? event : null),
    initialScope: {
      tags: {
        app_version: frontendRelease.version,
        git_sha: frontendRelease.shortGitSha,
      },
    },
  });
  sentryInitialized = true;
};

export const initFrontendMonitoring = () => {
  if (initialized) return;
  initialized = true;

  if (typeof window !== "undefined") {
    window.__MSCQR_RELEASE__ = frontendRelease;
  }

  registerSupportRuntimeListeners();
  initSentryIfConsented();

  if (typeof window !== "undefined") {
    window.addEventListener(CONSENT_CHANGED_EVENT, (event) => {
      const detail = (event as CustomEvent<ConsentState>).detail;
      if (detail?.categories.analytics) initSentryIfConsented();
    });
  }
};
