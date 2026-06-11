import cors from "cors";
import express from "express";
import os from "os";
import { z } from "zod";

import {
  buildCapabilitySummary,
  buildSetupVerification,
  isPreferredLabelPrinter,
  isVirtualNonLabelPrinter,
  listLocalPrinters,
  resolveSelectedPrinter,
  type LocalAgentPrinter,
  type LocalAgentSetupVerification,
} from "./cups";
import {
  loadAgentState,
  mergeCalibrationProfile,
  saveAgentState,
  setAgentBackendUrl,
  type AgentState,
  type CalibrationProfile,
} from "./state";
import { buildDiagnosticTestZplPayload } from "./render";
import { startGatewayWorker } from "./gateway";
import { startDirectPrintWorker } from "./directPrintWorker";
import { buildPrinterAgentHeartbeatPayload, signPrinterAgentPayload } from "../services/printerAgentSigningService";
import {
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} from "../services/localAgentProtocol";
import { randomOpaqueToken } from "./crypto";
import { resolveLocalPrintAgentBuildVersion, resolveLocalPrintAgentVersion } from "./version";

const app = express();

const PORT = Number(String(process.env.PRINT_AGENT_PORT || "17866").trim()) || 17866;
const HOST = String(process.env.PRINT_AGENT_HOST || "127.0.0.1").trim() || "127.0.0.1";
const AGENT_VERSION = resolveLocalPrintAgentVersion(process.env.PRINT_AGENT_VERSION);
const AGENT_BUILD_VERSION = resolveLocalPrintAgentBuildVersion(process.env.PRINT_AGENT_VERSION, process.env.PRINT_AGENT_BUILD_VERSION);
const INVENTORY_TTL_MS = Math.max(1500, Number(String(process.env.PRINT_AGENT_INVENTORY_TTL_MS || "5000").trim()) || 5000);
const cliArgs = new Set(process.argv.slice(2).map((arg) => String(arg || "").trim()));

type AgentSnapshot = {
  connected: boolean;
  printerName: string | null;
  printerId: string | null;
  selectedPrinterId: string | null;
  selectedPrinterName: string | null;
  deviceName: string;
  agentVersion: string;
  protocolVersion: string;
  buildVersion: string;
  transportDiagnosticsVersion: string;
  capabilities: typeof LOCAL_AGENT_CAPABILITIES;
  error: string | null;
  agentId: string;
  deviceFingerprint: string;
  publicKeyPem: string;
  backendConfigured: boolean;
  heartbeatNonce: string;
  heartbeatIssuedAt: string;
  heartbeatSignature: string;
  capabilitySummary: ReturnType<typeof buildCapabilitySummary>;
  printers: LocalAgentPrinter[];
  calibrationProfile: CalibrationProfile | null;
  setupVerification: LocalAgentSetupVerification;
};

let inventoryCache:
  | {
      expiresAt: number;
      snapshot: AgentSnapshot;
    }
  | null = null;

const resolveDeviceName = () => {
  const hostname = String(os.hostname() || "").trim();
  if (hostname && hostname.toUpperCase() !== "UNKNOWN") return hostname;
  try {
    const username = String(os.userInfo().username || "").trim();
    if (username) return `${username}-workstation`;
  } catch {
    // fallback below
  }
  return process.platform === "darwin" ? "macOS-workstation" : "workstation";
};

const buildVersionPayload = () => ({
  agentVersion: AGENT_VERSION,
  buildVersion: AGENT_BUILD_VERSION,
  protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
  capabilities: LOCAL_AGENT_CAPABILITIES,
});

const runSelfTest = async () => {
  const diagnosticZpl = buildDiagnosticTestZplPayload();
  const printerInventory = await listLocalPrinters().catch((error: any) => ({
    printers: [],
    error: error?.message || "Printer discovery self-test failed.",
  }));
  console.log(
    JSON.stringify(
      {
        ok: true,
        ...buildVersionPayload(),
        renderModule: {
          diagnosticZplBytes: Buffer.byteLength(diagnosticZpl, "utf8"),
          startsWithZplStart: diagnosticZpl.trim().startsWith("^XA"),
          endsWithZplEnd: diagnosticZpl.trim().endsWith("^XZ"),
        },
        printerDiscovery: {
          printerCount: printerInventory.printers.length,
          error: printerInventory.error || null,
        },
      },
      null,
      2
    )
  );
};

if (cliArgs.has("--version")) {
  console.log(AGENT_BUILD_VERSION);
  process.exit(0);
}

if (cliArgs.has("--version-json") || cliArgs.has("--status-json")) {
  console.log(JSON.stringify(buildVersionPayload(), null, 2));
  process.exit(0);
}

if (cliArgs.has("--self-test")) {
  runSelfTest()
    .then(() => process.exit(0))
    .catch((error: any) => {
      console.error(
        JSON.stringify(
          {
            ok: false,
            ...buildVersionPayload(),
            error: error?.message || "Local connector self-test failed.",
          },
          null,
          2
        )
      );
      process.exit(1);
    });
}

app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Private-Network", "true");
  next();
});
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Access-Control-Request-Private-Network"],
  })
);
app.use(express.json({ limit: "1mb" }));

const buildSnapshot = async (forceRefresh = false): Promise<{ state: AgentState; snapshot: AgentSnapshot }> => {
  if (!forceRefresh && inventoryCache && inventoryCache.expiresAt > Date.now()) {
    const state = await loadAgentState();
    return {
      state,
      snapshot: {
        ...inventoryCache.snapshot,
        calibrationProfile:
          inventoryCache.snapshot.selectedPrinterId
            ? state.calibrationProfiles[inventoryCache.snapshot.selectedPrinterId] || null
            : null,
      },
    };
  }

  let state = await loadAgentState();
  const inventory = await listLocalPrinters();
  const printers = inventory.printers;
  const selection = resolveSelectedPrinter(printers, state.selectedPrinterId);
  const resolvedSelectedId = selection.printerId;
  if (resolvedSelectedId !== state.selectedPrinterId) {
    state = {
      ...state,
      selectedPrinterId: resolvedSelectedId,
    };
    await saveAgentState(state);
  }

  const selectedPrinter = selection.printer;

  const connected = Boolean(selectedPrinter && selectedPrinter.online);
  const error =
    printers.length === 0
      ? inventory.error || "No printers detected by the local operating system."
      : !selectedPrinter
        ? "Select a printer before printing."
        : selectedPrinter.online
          ? null
          : `${selectedPrinter.printerName} is offline or paused.`;
  const setupVerification = buildSetupVerification({
    printers,
    selection,
    connected,
    inventoryError: inventory.error,
  });

  const snapshot: AgentSnapshot = {
    connected,
    printerName: selectedPrinter?.printerName || null,
    printerId: selectedPrinter?.printerId || null,
    selectedPrinterId: selectedPrinter?.printerId || null,
    selectedPrinterName: selectedPrinter?.printerName || null,
    deviceName: resolveDeviceName(),
    agentVersion: AGENT_VERSION,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: LOCAL_AGENT_CAPABILITIES,
    error,
    agentId: state.agentId,
    deviceFingerprint: state.deviceFingerprint,
    publicKeyPem: state.publicKeyPem,
    backendConfigured: Boolean(state.backendUrl || process.env.PRINT_AGENT_BACKEND_URL || process.env.PRINT_GATEWAY_BACKEND_URL),
    ...buildSignedHeartbeat({
      state,
      printerId: selectedPrinter?.printerId || null,
      connected,
    }),
    capabilitySummary: buildCapabilitySummary(printers, selection.printerId),
    printers,
    calibrationProfile: selectedPrinter ? state.calibrationProfiles[selectedPrinter.printerId] || null : null,
    setupVerification,
  };

  inventoryCache = {
    expiresAt: Date.now() + INVENTORY_TTL_MS,
    snapshot,
  };

  return { state, snapshot };
};

const invalidateInventoryCache = () => {
  inventoryCache = null;
};

const buildSignedHeartbeat = (params: {
  state: AgentState;
  printerId: string | null;
  connected: boolean;
}) => {
  const heartbeatNonce = randomOpaqueToken(12);
  const heartbeatIssuedAt = new Date().toISOString();
  const payload = buildPrinterAgentHeartbeatPayload({
    userId: "manufacturer-browser-heartbeat",
    agentId: params.state.agentId,
    deviceFingerprint: params.state.deviceFingerprint,
    printerId: params.printerId || "unknown-printer",
    connected: params.connected,
    heartbeatNonce,
    heartbeatIssuedAt,
  });

  return {
    heartbeatNonce,
    heartbeatIssuedAt,
    heartbeatSignature: signPrinterAgentPayload(params.state.privateKeyPem, payload),
  };
};

const requirePrinter = async (printerId: string | null | undefined) => {
  const { state, snapshot } = await buildSnapshot(true);
  const explicitPrinterId = String(printerId || "").trim();
  const resolvedPrinterId = String(explicitPrinterId || snapshot.selectedPrinterId || "").trim();
  const printer =
    snapshot.printers.find((item) => item.printerId === resolvedPrinterId) ||
    snapshot.printers.find((item) => item.isDefault) ||
    snapshot.printers[0] ||
    null;

  if (!printer) {
    throw Object.assign(new Error("No local printer is available."), { statusCode: 404 });
  }

  if (!printer.online) {
    throw Object.assign(new Error(`${printer.printerName} is offline.`), { statusCode: 409 });
  }

  if (
    explicitPrinterId &&
    isVirtualNonLabelPrinter(printer) &&
    snapshot.printers.some((item) => item.online !== false && isPreferredLabelPrinter(item))
  ) {
    throw Object.assign(
      new Error("Fax/PDF printers cannot be used for MSCQR labels. Choose the ZDesigner label printer."),
      { statusCode: 409 }
    );
  }

  return { state, snapshot, printer };
};

app.get("/status", async (_req, res) => {
  try {
    const { snapshot } = await buildSnapshot();
    res.json(snapshot);
  } catch (error: any) {
    res.status(500).json({
      connected: false,
      error: error?.message || "Local print agent failed to inspect printers.",
      printers: [],
      setupVerification: {
        state: "PRINTER_UNAVAILABLE",
        success: false,
        message: error?.message || "Local print agent failed to inspect printers.",
        printerCount: 0,
        onlinePrinterCount: 0,
        selectedPrinterId: null,
        selectedPrinterName: null,
        selectionSource: "none",
      },
    });
  }
});

app.get("/printers", async (_req, res) => {
  try {
    const { snapshot } = await buildSnapshot();
    res.json({
      success: true,
      printers: snapshot.printers,
      selectedPrinterId: snapshot.selectedPrinterId,
      selectedPrinterName: snapshot.selectedPrinterName,
      connected: snapshot.connected,
      error: snapshot.error,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error?.message || "Local printer discovery failed.",
    });
  }
});

const selectPrinter = async (req: express.Request, res: express.Response) => {
  try {
    const printerId = String(req.body?.printerId || "").trim();
    if (!printerId) {
      return res.status(400).json({ success: false, error: "printerId is required" });
    }
    const { state, snapshot, printer } = await requirePrinter(printerId);
    const nextState: AgentState = {
      ...state,
      selectedPrinterId: printer.printerId,
    };
    await saveAgentState(nextState);
    invalidateInventoryCache();
    return res.json({
      success: true,
      selectedPrinterId: printer.printerId,
      selectedPrinterName: printer.printerName,
      printers: snapshot.printers,
    });
  } catch (error: any) {
    return res.status(error?.statusCode || 500).json({
      success: false,
      error: error?.message || "Could not switch local printer.",
    });
  }
};

app.post("/printer/select", selectPrinter);
app.post("/printers/select", selectPrinter);

const saveCalibration = async (req: express.Request, res: express.Response) => {
  try {
    const printerId = String(req.body?.printerId || "").trim();
    if (!printerId) {
      return res.status(400).json({ success: false, error: "printerId is required" });
    }

    const { state, printer } = await requirePrinter(printerId);
    const nextState = mergeCalibrationProfile(state, printer.printerId, req.body || {});
    await saveAgentState(nextState);
    invalidateInventoryCache();

    return res.json({
      success: true,
      printerId: printer.printerId,
      calibrationProfile: nextState.calibrationProfiles[printer.printerId] || null,
    });
  } catch (error: any) {
    return res.status(error?.statusCode || 500).json({
      success: false,
      error: error?.message || "Could not save calibration profile.",
    });
  }
};

app.post("/printer/calibration", saveCalibration);
app.post("/printers/calibration", saveCalibration);

const backendConfigSchema = z
  .object({
    backendUrl: z.string().trim().url().max(500),
  })
  .strict();

app.post("/backend/config", async (req, res) => {
  try {
    const parsed = backendConfigSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "backendUrl is required" });
    }

    const state = await loadAgentState();
    const nextState = setAgentBackendUrl(state, parsed.data.backendUrl);
    await saveAgentState(nextState);
    invalidateInventoryCache();

    return res.json({
      success: true,
      backendUrl: nextState.backendUrl,
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      error: error?.message || "Could not save backend connection details.",
    });
  }
});

app.post("/print", async (_req, res) => {
  return res.status(410).json({
    success: false,
    error:
      "Legacy browser-submitted local printing has been disabled. Create a controlled MSCQR print job so the connector can claim approved work directly from the server.",
  });
});

if (!cliArgs.has("--self-test")) {
  app.listen(PORT, HOST, () => {
    console.log(`MSCQR local print agent listening on http://${HOST}:${PORT}`);
    startGatewayWorker();
    startDirectPrintWorker();
  });
}
