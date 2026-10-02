import React, { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { clientSecurityScope, getRequestCoordinatorScope, isRequestCoordinatorUserCurrent, onRequestCoordinatorScopeChange } from "@/lib/api/request-coordinator";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import { TrackingWorkspace } from "@/features/tracking/components/TrackingWorkspace";
import {
  type BatchSummaryRow,
  type ScanLogRow,
  type TrackingEventSummary,
  type TrackingFilterState,
} from "@/features/tracking/types";
import apiClient from "@/lib/api-client";
import { onMutationEvent } from "@/lib/mutation-events";

const asIsoStart = (dateValue?: string) => (dateValue ? new Date(`${dateValue}T00:00:00`).toISOString() : undefined);
const asIsoEnd = (dateValue?: string) => (dateValue ? new Date(`${dateValue}T23:59:59.999`).toISOString() : undefined);

export default function QRTracking() {
  const { user } = useAuth();

  const [summary, setSummary] = useState<BatchSummaryRow[]>([]);
  const [logs, setLogs] = useState<ScanLogRow[]>([]);
  const [scopeMeta, setScopeMeta] = useState<{
    mode: "inventory" | "activity";
    title: string;
    description: string;
    quantities: { distinctCodes: number; scanEvents: number; matchedBatches: number };
  } | null>(null);
  const [analyticsTotals, setAnalyticsTotals] = useState({
    total: 0,
    dormant: 0,
    allocated: 0,
    printed: 0,
    redeemed: 0,
    blocked: 0,
    created: 0,
    scanEvents: 0,
  });
  const [analyticsTrend, setAnalyticsTrend] = useState<any[]>([]);
  const [eventSummary, setEventSummary] = useState<TrackingEventSummary>({
    totalScanEvents: 0,
    firstScanEvents: 0,
    repeatScanEvents: 0,
    blockedEvents: 0,
    trustedOwnerEvents: 0,
    externalEvents: 0,
    namedLocationEvents: 0,
    knownDeviceEvents: 0,
  });
  const [licensees, setLicensees] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allocationMapOpen, setAllocationMapOpen] = useState(false);
  const [allocationMapLoading, setAllocationMapLoading] = useState(false);
  const [allocationMap, setAllocationMap] = useState<any | null>(null);

  const [filters, setFilters] = useState<TrackingFilterState>({
    code: "",
    batchQuery: "",
    status: "all",
    firstScan: "all",
    fromDate: "",
    toDate: "",
    licenseeId: "all",
    outcome: "all",
    riskBand: "all",
    replacementStatus: "all",
    customerTrustReviewState: "all",
  });

  const isSuperAdmin = user?.role === "super_admin";
  const scopedLicenseeId = isSuperAdmin && filters.licenseeId !== "all" ? filters.licenseeId : undefined;
  const securityScope = useSyncExternalStore(onRequestCoordinatorScopeChange, getRequestCoordinatorScope, getRequestCoordinatorScope);
  const effectiveScope = JSON.stringify([securityScope, clientSecurityScope(user), isSuperAdmin ? filters.licenseeId : null]);
  const currentScope = useRef(effectiveScope);
  currentScope.current = effectiveScope;
  const [resultScope, setResultScope] = useState("");
  const [mapScope, setMapScope] = useState("");
  const scopeIsCurrent = resultScope === effectiveScope && isRequestCoordinatorUserCurrent(user);
  const loadSequence = useRef(0);

  const load = async (opts?: { silent?: boolean; override?: Partial<TrackingFilterState> }) => {
    const sequence = ++loadSequence.current;
    if (!user || !isRequestCoordinatorUserCurrent(user) || securityScope !== getRequestCoordinatorScope()) return;
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    const current = { ...filters, ...(opts?.override || {}) };

    try {
      if (isSuperAdmin && current.licenseeId === "all") {
        throw new Error("Select a licensee to view tenant-scoped QR analytics.");
      }
      const response = await apiClient.getQrTrackingAnalytics({
        licenseeId: isSuperAdmin && current.licenseeId !== "all" ? current.licenseeId : undefined,
        code: current.code.trim() || undefined,
        batchQuery: current.batchQuery.trim() || undefined,
        status: current.status !== "all" ? (current.status as any) : undefined,
        onlyFirstScan: current.firstScan === "yes" ? true : current.firstScan === "no" ? false : undefined,
        from: asIsoStart(current.fromDate),
        to: asIsoEnd(current.toDate),
        limit: 200,
      });

      if (sequence !== loadSequence.current || currentScope.current !== effectiveScope || securityScope !== getRequestCoordinatorScope()) return;
      if (!response.success || !response.data) {
        throw new Error(response.error || "Failed to load tracking analytics");
      }

      const payload: any = response.data;
      setResultScope(effectiveScope);
      setSummary(Array.isArray(payload.batches) ? payload.batches : []);
      setLogs(Array.isArray(payload.logs) ? payload.logs : []);
      setAnalyticsTotals({
        total: Number(payload.totals?.total || 0),
        dormant: Number(payload.totals?.dormant || 0),
        allocated: Number(payload.totals?.allocated || 0),
        printed: Number(payload.totals?.printed || 0),
        redeemed: Number(payload.totals?.redeemed || 0),
        blocked: Number(payload.totals?.blocked || 0),
        created: Number(payload.totals?.created || 0),
        scanEvents: Number(payload.eventSummary?.totalScanEvents || payload.scope?.quantities?.scanEvents || 0),
      });
      setAnalyticsTrend(Array.isArray(payload.trend) ? payload.trend : []);
      setScopeMeta(payload.scope || null);
      setEventSummary({
        totalScanEvents: Number(payload.eventSummary?.totalScanEvents || 0),
        firstScanEvents: Number(payload.eventSummary?.firstScanEvents || 0),
        repeatScanEvents: Number(payload.eventSummary?.repeatScanEvents || 0),
        blockedEvents: Number(payload.eventSummary?.blockedEvents || 0),
        trustedOwnerEvents: Number(payload.eventSummary?.trustedOwnerEvents || 0),
        externalEvents: Number(payload.eventSummary?.externalEvents || 0),
        namedLocationEvents: Number(payload.eventSummary?.namedLocationEvents || 0),
        knownDeviceEvents: Number(payload.eventSummary?.knownDeviceEvents || 0),
      });
    } catch (nextError: any) {
      if (sequence !== loadSequence.current || currentScope.current !== effectiveScope || securityScope !== getRequestCoordinatorScope()) return;
      setResultScope(effectiveScope);
      setError(nextError?.message || "Failed to load tracking data");
      setSummary([]);
      setLogs([]);
      setAnalyticsTrend([]);
      setScopeMeta(null);
      setEventSummary({
        totalScanEvents: 0,
        firstScanEvents: 0,
        repeatScanEvents: 0,
        blockedEvents: 0,
        trustedOwnerEvents: 0,
        externalEvents: 0,
        namedLocationEvents: 0,
        knownDeviceEvents: 0,
      });
      setAnalyticsTotals({
        total: 0,
        dormant: 0,
        allocated: 0,
        printed: 0,
        redeemed: 0,
        blocked: 0,
        created: 0,
        scanEvents: 0,
      });
    } finally {
      if (sequence === loadSequence.current) setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    return () => { loadSequence.current += 1; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveScope]);

  useEffect(() => {
    setLicensees([]);
    if (!isSuperAdmin) return;
    apiClient.getLicensees().then((response) => {
      if (securityScope !== getRequestCoordinatorScope()) return;
      if (!response.success) return;
      setLicensees((response.data as any[]) || []);
    });
  }, [isSuperAdmin, securityScope]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      void load({ silent: true });
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, effectiveScope]);

  const batchNameById = useMemo(() => {
    const map = new Map<string, string>();
    summary.forEach((batch) => map.set(batch.id, batch.name || batch.id));
    return map;
  }, [summary]);

  const matchesDecisionFilters = (latestDecision?: BatchSummaryRow["latestDecision"] | ScanLogRow["latestDecision"] | null) => {
    if (filters.outcome !== "all" && String(latestDecision?.outcome || "") !== filters.outcome) return false;
    if (filters.riskBand !== "all" && String(latestDecision?.riskBand || "") !== filters.riskBand) return false;
    if (filters.replacementStatus !== "all" && String(latestDecision?.replacementStatus || "") !== filters.replacementStatus) return false;
    if (
      filters.customerTrustReviewState !== "all" &&
      String(latestDecision?.customerTrustReviewState || "") !== filters.customerTrustReviewState
    ) {
      return false;
    }
    return true;
  };

  const filteredSummary = useMemo(
    () => summary.filter((batch) => matchesDecisionFilters(batch.latestDecision || null)),
    [filters.customerTrustReviewState, filters.outcome, filters.replacementStatus, filters.riskBand, summary]
  );
  const filteredLogs = useMemo(
    () => logs.filter((log) => matchesDecisionFilters(log.latestDecision || null)),
    [filters.customerTrustReviewState, filters.outcome, filters.replacementStatus, filters.riskBand, logs]
  );

  const friendlyError = useMemo(() => {
    const message = String(error || "").toLowerCase();
    if (!message) return "";
    if (message.includes("internal server error") || message.includes("http 500")) {
      return "Scan activity is temporarily unavailable. Please refresh in a moment.";
    }
    if (message.includes("network") || message.includes("timeout") || message.includes("offline")) {
      return "Network connection issue while loading scan activity. Check connectivity and retry.";
    }
    return "We could not load scan activity. Please retry.";
  }, [error]);

  const openAllocationMap = async (batchId: string) => {
    setMapScope(effectiveScope);
    setAllocationMapOpen(true);
    setAllocationMapLoading(true);
    setAllocationMap(null);
    try {
      if (isSuperAdmin && !scopedLicenseeId) throw new Error("Select a brand before opening its allocation map.");
      const response = await apiClient.getBatchAllocationMap(batchId, scopedLicenseeId);
      if (currentScope.current !== effectiveScope || securityScope !== getRequestCoordinatorScope()) return;
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not load allocation details.");
      }
      setAllocationMap(response.data);
    } catch (nextError: any) {
      if (currentScope.current !== effectiveScope || securityScope !== getRequestCoordinatorScope()) return;
      setAllocationMapOpen(false);
      setError(nextError?.message || "Could not load allocation details.");
    } finally {
      if (currentScope.current === effectiveScope) setAllocationMapLoading(false);
    }
  };

  return (
    <DashboardLayout>
      <TrackingWorkspace
        role={user?.role || null}
        loading={loading || (!!user && !scopeIsCurrent)}
        error={scopeIsCurrent ? error : null}
        friendlyError={scopeIsCurrent ? friendlyError : ""}
        blockedLogCount={scopeIsCurrent ? eventSummary.blockedEvents : 0}
        firstScanCount={scopeIsCurrent ? eventSummary.firstScanEvents : 0}
        eventSummary={scopeIsCurrent ? eventSummary : { totalScanEvents: 0, firstScanEvents: 0, repeatScanEvents: 0, blockedEvents: 0, trustedOwnerEvents: 0, externalEvents: 0, namedLocationEvents: 0, knownDeviceEvents: 0 }}
        analyticsTotals={scopeIsCurrent ? analyticsTotals : { total: 0, dormant: 0, allocated: 0, printed: 0, redeemed: 0, blocked: 0, created: 0, scanEvents: 0 }}
        analyticsTrend={scopeIsCurrent ? analyticsTrend : []}
        scopeMeta={scopeIsCurrent ? scopeMeta : null}
        filters={filters}
        onFiltersChange={setFilters}
        onLoad={load}
        isSuperAdmin={isSuperAdmin}
        scopedLicenseeId={scopedLicenseeId}
        licensees={licensees}
        summary={scopeIsCurrent ? filteredSummary : []}
        logs={scopeIsCurrent ? filteredLogs : []}
        batchNameById={batchNameById}
        onOpenAllocationMap={openAllocationMap}
        allocationMapOpen={allocationMapOpen && mapScope === effectiveScope}
        allocationMapLoading={allocationMapLoading}
        allocationMap={mapScope === effectiveScope ? allocationMap : null}
        onAllocationMapOpenChange={(open) => {
          setAllocationMapOpen(open);
          if (!open) {
            setAllocationMap(null);
            setAllocationMapLoading(false);
          }
        }}
      />
    </DashboardLayout>
  );
}
