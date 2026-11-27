import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";

import apiClient from "@/lib/api-client";
import { isActivePrintSessionSuppressed, useActivePrintSessionSuppression } from "@/lib/active-print-session";
import { getRequestCoordinatorScope, isRequestCoordinatorUserCurrent, onRequestCoordinatorScopeChange } from "@/lib/api/request-coordinator";
import { canPollVisibleDocument, pollingPolicy } from "@/lib/query-polling-policy";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";
import { printerConnectionStatusSchema } from "../../../shared/contracts/runtime/printing";
import { createManufacturerPrinterFailureReporter } from "@/features/layout/manufacturerPrinterFailureReporter";
import { defaultPrinterStatus, DISABLE_E2E_PRINTER_AGENT_POLLING } from "@/features/layout/manufacturerPrinterConnectionUtils";
import type { User } from "@/types";
import type { PrinterConnectionStatusDTO } from "../../../shared/contracts/runtime/printing";
import { loadManufacturerPrinterRuntimeSnapshot, normalizeLocalPrinterRows, type ManufacturerPrinterRuntime } from "./hooks";

const unavailable = "Printer verification is unavailable. Refresh printer status and try again.";
const checking = "Checking current printer verification.";
const expired = "Printer attestation expired.";
// The guarded persistent printing path requires a signed heartbeat within 35 seconds.
const evidenceLifetimeMs = 35_000;

const empty: ManufacturerPrinterRuntime = {
  localAgent: { reachable: false, connected: false, error: null, checkedAt: null },
  remoteStatus: defaultPrinterStatus,
  detectedPrinters: [], registeredPrinters: [], preferredPrinterId: null, localInventory: [], localBinding: null,
};

function blocked(status: PrinterConnectionStatusDTO, reason: string) {
  return { ...status, trusted: false, eligibleForPrinting: false, stale: true, trustReason: reason };
}

function evidenceDeadline(status: PrinterConnectionStatusDTO) {
  const attestation = status.signedAttestation;
  if (!attestation?.present || !attestation.signatureValid || !attestation.fresh) return NaN;
  return Math.min(Date.parse(attestation.issuedAt || ""), Date.parse(status.lastHeartbeatAt || "")) + evidenceLifetimeMs;
}

function reconcile(snapshot: ManufacturerPrinterRuntime, expectedPrinter: string | null): ManufacturerPrinterRuntime {
  const { remoteStatus: status, localBinding: local, localAgent, registeredPrinters } = snapshot;
  const unverified = { ...snapshot, deviceVerified: false };
  if (!buildSecurePrintReadiness(status).ready) return unverified;

  const selected = status.selectedPrinterId;
  const matchesDevice = Boolean(selected && status.registrationId && local?.printerId === selected &&
    (!expectedPrinter || selected === expectedPrinter) &&
    local.agentId && local.agentId === status.agentId &&
    local.deviceFingerprint && local.deviceFingerprint === status.deviceFingerprint);

  if (!localAgent.connected) {
    return { ...unverified, remoteStatus: { ...blocked(status, "Printer helper is disconnected."), connected: false, stale: false } };
  }
  if (!matchesDevice || normalizeLocalPrinterRows(snapshot.localInventory).some((row) => row.printerId === selected && row.online === false)) {
    return { ...unverified, remoteStatus: blocked(status, "Check the selected printer and its connection.") };
  }
  const deadline = evidenceDeadline(status);
  if (!Number.isFinite(deadline) || deadline <= Date.now()) {
    return { ...unverified, remoteStatus: blocked(status, expired) };
  }
  const savedBindingMatches = registeredPrinters.some((row) => row.isActive && row.connectionType === "LOCAL_AGENT" &&
    row.printerRegistrationId === status.registrationId && (row.nativePrinterId || row.id) === selected);
  return { ...snapshot, deviceVerified: true, remoteStatus: savedBindingMatches
    ? status : blocked(status, "Check the saved printer setup for this connector.") };
}

type RefreshOptions = { force?: boolean };
type Refresh = (options?: RefreshOptions) => Promise<ManufacturerPrinterRuntime | null>;

function useRuntimeOwner(user: User) {
  const scope = useSyncExternalStore(onRequestCoordinatorScopeChange, getRequestCoordinatorScope, getRequestCoordinatorScope);
  const authorized = user.role === "manufacturer" && isRequestCoordinatorUserCurrent(user);
  const suppressed = useActivePrintSessionSuppression();
  const [entry, setEntry] = useState({ scope, snapshot: empty });
  const [checkingScope, setCheckingScope] = useState<string | null>(null);
  const [liveScope, setLiveScope] = useState<string | null>(null);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const latest = useRef(entry);
  const revision = useRef(0);
  const expectedPrinter = useRef<string | null>(null);
  const lastEventTime = useRef(0);
  const configured = useRef(false);
  const mounted = useRef(false);
  const changingPrinter = useRef(false);
  const lastReconciliation = useRef(0);
  const needsSnapshot = useRef(true);
  const failureReport = useRef({ signature: "", at: 0 });
  const failureReportInFlight = useRef(false);
  const flight = useRef<{
    scope: string; revision: number; force: boolean; promise: ReturnType<Refresh>; queued?: ReturnType<Refresh>;
  } | null>(null);

  const current = () => mounted.current && scopeRef.current === scope && getRequestCoordinatorScope() === scope;
  const reportFailure = createManufacturerPrinterFailureReporter({
    user, isCurrent: current, printerFailureReportRef: failureReport, printerFailureInFlightRef: failureReportInFlight,
  });
  const snapshotForScope = () => latest.current.scope === scope ? latest.current.snapshot : empty;
  const publish = (snapshot: ManufacturerPrinterRuntime) => {
    if (!current()) return;
    latest.current = { scope, snapshot };
    setEntry(latest.current);
  };
  const invalidate = (reason = unavailable) => {
    ++revision.current;
    needsSnapshot.current = true;
    const snapshot = snapshotForScope();
    publish({ ...snapshot, deviceVerified: false, remoteStatus: blocked(snapshot.remoteStatus, reason) });
  };

  const refresh: Refresh = (options) => {
    const force = options?.force || needsSnapshot.current;
    if (!authorized || !current() || changingPrinter.current || isActivePrintSessionSuppressed() || !canPollVisibleDocument()) return Promise.resolve(null);
    const active = flight.current;
    if (active?.scope === scope) {
      if (active.revision === revision.current && (!force || active.force)) return active.promise;
      if (!active.queued) {
        invalidate(checking);
        active.queued = active.promise.then(() => refresh({ force: true }));
      }
      return active.queued;
    }

    const started = revision.current;
    const prior = snapshotForScope();
    const eventAtStart = lastEventTime.current;
    if (force) publish({ ...prior, deviceVerified: false, remoteStatus: blocked(prior.remoteStatus, checking) });
    setCheckingScope(scope);
    const request = { scope, revision: started, force, promise: Promise.resolve<ManufacturerPrinterRuntime | null>(null) };
    request.promise = (async () => {
      try {
        const snapshot = await loadManufacturerPrinterRuntimeSnapshot(true, { force, previous: prior });
        if (!current() || started !== revision.current || isActivePrintSessionSuppressed()) return null;
        if (!configured.current && snapshot.localAgent.reachable && !snapshot.authorizationRejected) {
          configured.current = true;
          void apiClient.configureLocalPrintAgentBackend(window.location.origin)?.then((response) => {
            if (current() && !response?.success) configured.current = false;
          }, () => { if (current()) configured.current = false; });
        }
        const { localResult, ...facts } = snapshot;
        const streamStatus = snapshotForScope().remoteStatus;
        const useNewerStream = !needsSnapshot.current && lastEventTime.current > eventAtStart &&
          !snapshot.authorizationRejected && snapshot.remoteStatus.trustStatus !== "UNAVAILABLE" &&
          Date.parse(streamStatus.lastHeartbeatAt || "") > Date.parse(snapshot.remoteStatus.lastHeartbeatAt || "");
        const next = reconcile({ ...facts, remoteStatus: useNewerStream ? streamStatus : facts.remoteStatus }, expectedPrinter.current);
        needsSnapshot.current = !buildSecurePrintReadiness(next.remoteStatus).ready;
        if (!needsSnapshot.current) expectedPrinter.current = null;
        publish(next);
        if (localResult && !DISABLE_E2E_PRINTER_AGENT_POLLING) {
          void reportFailure({ localResult, remoteStatus: next.remoteStatus, printers: next.detectedPrinters });
        }
        return next;
      } catch {
        if (current() && started === revision.current) invalidate();
        return null;
      } finally {
        if (flight.current === request) flight.current = null;
        if (current()) setCheckingScope(null);
      }
    })();
    flight.current = request;
    return request.promise;
  };

  const changePrinter = async (id: string) => {
    if (!authorized || !current() || changingPrinter.current || isActivePrintSessionSuppressed()) return null;
    changingPrinter.current = true;
    expectedPrinter.current = id;
    invalidate("Printer selection changed. Refresh printer verification.");
    try {
      const response = await apiClient.selectLocalPrinter(id);
      if (!current()) return null;
      changingPrinter.current = false;
      if (!response.success) expectedPrinter.current = null;
      await refresh({ force: true });
      return response;
    } catch {
      if (current()) {
        changingPrinter.current = false;
        expectedPrinter.current = null;
        invalidate();
      }
      return null;
    }
  };

  useEffect(() => {
    mounted.current = true;
    expectedPrinter.current = null;
    changingPrinter.current = false;
    needsSnapshot.current = true;
    lastReconciliation.current = 0;
    failureReport.current = { signature: "", at: 0 };
    configured.current = false;
    lastEventTime.current = 0;
    ++revision.current;
    publish(empty);
    let active = true;
    queueMicrotask(() => { if (active) void refresh({ force: true }); });
    const onVisibility = () => {
      if (document.visibilityState === "hidden") invalidate(expired);
      else void refresh({ force: true });
    };
    if (authorized) document.addEventListener("visibilitychange", onVisibility);
    return () => {
      active = false;
      mounted.current = false;
      ++revision.current;
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // Lifecycle is keyed to the authenticated scope generation, independent of routes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, authorized]);

  useEffect(() => {
    if (!authorized || suppressed || DISABLE_E2E_PRINTER_AGENT_POLLING) return;
    let active = true;
    let stop: (() => void) | undefined;
    queueMicrotask(() => {
      if (!active || !current()) return;
      stop = apiClient.streamPrinterConnectionStatus(({ status: eventStatus, serverTime }) => {
        if (!active || !current() || !canPollVisibleDocument() || isActivePrintSessionSuppressed()) return;
        const sent = Date.parse(serverTime || "");
        if (!Number.isFinite(sent) || sent <= lastEventTime.current) return;
        lastEventTime.current = sent;
        setLiveScope(scope);
        const parsed = printerConnectionStatusSchema.safeParse(eventStatus);
        if (!parsed.success) {
          invalidate();
          return;
        }
        const status = parsed.data;
        const snapshot = snapshotForScope();
        const previous = snapshot.remoteStatus;
        const sameBinding = status.registrationId === previous.registrationId && status.agentId === previous.agentId &&
          status.deviceFingerprint === previous.deviceFingerprint && status.selectedPrinterId === previous.selectedPrinterId;
        const next = reconcile({ ...snapshot, remoteStatus: status }, expectedPrinter.current);
        if (sameBinding && !needsSnapshot.current && buildSecurePrintReadiness(next.remoteStatus).ready) {
          if (Date.parse(status.lastHeartbeatAt || "") >= Date.parse(previous.lastHeartbeatAt || "")) publish(next);
          return;
        }
        if (!needsSnapshot.current) invalidate();
        if (!buildSecurePrintReadiness(status).ready && !changingPrinter.current) {
          if (!snapshot.authorizationRejected) publish({ ...snapshotForScope(), deviceVerified: false, remoteStatus: status });
          return;
        }
        const now = Date.now();
        if (!flight.current && now - lastReconciliation.current >= pollingPolicy.printerRuntimeRefreshMs) {
          lastReconciliation.current = now;
          void refresh({ force: true });
        }
      }, () => {
        if (!active || !current()) return;
        setLiveScope(null);
        invalidate();
      });
    });
    return () => {
      active = false;
      stop?.();
      setLiveScope(null);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, authorized, suppressed]);

  const wasSuppressed = useRef(suppressed);
  useEffect(() => {
    if (wasSuppressed.current && !suppressed) void refresh({ force: true });
    wasSuppressed.current = suppressed;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [suppressed]);

  const snapshot = authorized && entry.scope === scope ? entry.snapshot : empty;
  const live = liveScope === scope && !suppressed;
  const ready = buildSecurePrintReadiness(snapshot.remoteStatus).ready;
  useEffect(() => {
    if (!authorized || suppressed || (live && ready) || DISABLE_E2E_PRINTER_AGENT_POLLING) return;
    const timer = window.setInterval(() => { void refresh(); }, pollingPolicy.printerRuntimeRefreshMs);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, authorized, suppressed, live, ready]);

  const deadline = snapshot.deviceVerified ? evidenceDeadline(snapshot.remoteStatus) : NaN;
  useEffect(() => {
    if (!Number.isFinite(deadline)) return;
    const timer = window.setTimeout(() => {
      if (current() && snapshotForScope() === snapshot) invalidate(expired);
    }, Math.max(0, deadline - Date.now()));
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, snapshot, deadline]);

  return { scope, snapshot, checking: checkingScope === scope, live, suppressed, refresh, invalidate, changePrinter };
}

const Context = createContext<ReturnType<typeof useRuntimeOwner> | null>(null);

export function ManufacturerPrinterRuntimeProvider({ user, children }: { user: User; children: ReactNode }) {
  const runtime = useRuntimeOwner(user);
  return <Context.Provider value={runtime}>{children}</Context.Provider>;
}

export function useManufacturerPrinterRuntime() {
  return useContext(Context);
}
