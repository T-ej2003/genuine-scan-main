import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";

import apiClient from "@/lib/api-client";
import { isActivePrintSessionSuppressed } from "@/lib/active-print-session";
import { pollingPolicy } from "@/lib/query-polling-policy";

const getDeviceType = () => {
  const ua = navigator.userAgent || "";
  if (/mobile/i.test(ua)) return "mobile";
  if (/tablet|ipad/i.test(ua)) return "tablet";
  return "desktop";
};

const getNetworkType = () => {
  const conn = (navigator as any).connection;
  return String(conn?.effectiveType || conn?.type || "unknown");
};

const TELEMETRY_STORAGE_PREFIX = "mscqr:route-transition:v1:";
const DISABLE_E2E_TELEMETRY = import.meta.env.VITE_E2E_DISABLE_TELEMETRY === "true";

const recentlySentRouteTransition = (signature: string, ttlMs: number) => {
  try {
    const key = `${TELEMETRY_STORAGE_PREFIX}${signature}`;
    const previous = Number(window.localStorage.getItem(key) || "0");
    if (Number.isFinite(previous) && Date.now() - previous < ttlMs) return true;
    window.localStorage.setItem(key, String(Date.now()));
    return false;
  } catch {
    return false;
  }
};

const shouldSampleRouteTransition = (routeFrom: string, routeTo: string) => {
  if (routeFrom.startsWith("/verify") || routeTo.startsWith("/verify") || routeFrom.startsWith("/scan") || routeTo.startsWith("/scan")) {
    return true;
  }
  return Math.random() < pollingPolicy.telemetryRouteSampleRate;
};

export default function RouteMetricsTracker() {
  const location = useLocation();
  const route = `${location.pathname}${location.search}`;
  const prevRef = useRef<{ route: string; at: number } | null>(null);
  const lastSentRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });

  useEffect(() => {
    const now = typeof performance !== "undefined" ? performance.now() : Date.now();

    if (DISABLE_E2E_TELEMETRY) {
      prevRef.current = { route, at: now };
      return;
    }

    if (isActivePrintSessionSuppressed()) {
      prevRef.current = { route, at: now };
      return;
    }

    if (prevRef.current && prevRef.current.route !== route) {
      const transitionMs = Math.max(0, Math.round(now - prevRef.current.at));
      const payload = {
        routeFrom: prevRef.current.route,
        routeTo: route,
        source: "route_transition",
        transitionMs,
        deviceType: getDeviceType(),
        networkType: getNetworkType(),
        online: navigator.onLine,
        verifyCodePresent: route.startsWith("/verify/") || route.includes("/scan"),
      };
      const signature = `${payload.routeFrom}->${payload.routeTo}`;
      if (
        payload.routeTo &&
        payload.routeTo.length <= 300 &&
        payload.routeFrom.length <= 300 &&
        Number.isInteger(payload.transitionMs) &&
        payload.transitionMs <= 120_000 &&
        shouldSampleRouteTransition(payload.routeFrom, payload.routeTo) &&
        !recentlySentRouteTransition(signature, pollingPolicy.telemetryRouteDebounceMs) &&
        !(
          lastSentRef.current.signature === signature &&
          Date.now() - lastSentRef.current.at < pollingPolicy.telemetryRouteDebounceMs
        )
      ) {
        lastSentRef.current = { signature, at: Date.now() };

        apiClient.captureRouteTransition(payload).then((response) => {
          if (response.status === 400) {
            lastSentRef.current = { signature, at: Date.now() + 60_000 };
          }
        }).catch(() => {
          // best effort telemetry
        });
      }
    }

    prevRef.current = { route, at: now };
  }, [route]);

  return null;
}
