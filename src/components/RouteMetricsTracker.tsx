import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";

import apiClient from "@/lib/api-client";

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

export default function RouteMetricsTracker() {
  const location = useLocation();
  const route = `${location.pathname}${location.search}`;
  const prevRef = useRef<{ route: string; at: number } | null>(null);

  useEffect(() => {
    const now = typeof performance !== "undefined" ? performance.now() : Date.now();

    if (prevRef.current && prevRef.current.route !== route) {
      const payload = {
        routeFrom: prevRef.current.route,
        routeTo: route,
        source: "route_transition",
        transitionMs: Math.max(0, Math.round(now - prevRef.current.at)),
        deviceType: getDeviceType(),
        networkType: getNetworkType(),
        online: navigator.onLine,
        verifyCodePresent: route.startsWith("/verify/") || route.includes("/scan"),
      };

      apiClient.captureRouteTransition(payload).catch(() => {
        // best effort telemetry
      });
    }

    prevRef.current = { route, at: now };
  }, [route]);

  return null;
}
