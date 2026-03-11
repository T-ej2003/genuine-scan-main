import cors from "cors";
import express from "express";
import os from "os";

import { buildCapabilitySummary, listLocalPrinters, type LocalAgentPrinter } from "./cups";
import { printLabel } from "./render";
import {
  loadAgentState,
  mergeCalibrationProfile,
  saveAgentState,
  type AgentState,
  type CalibrationProfile,
} from "./state";

const app = express();

const PORT = Number(String(process.env.PRINT_AGENT_PORT || "17866").trim()) || 17866;
const HOST = String(process.env.PRINT_AGENT_HOST || "127.0.0.1").trim() || "127.0.0.1";
const AGENT_VERSION = String(process.env.PRINT_AGENT_VERSION || "1.0.0").trim() || "1.0.0";
const INVENTORY_TTL_MS = Math.max(1500, Number(String(process.env.PRINT_AGENT_INVENTORY_TTL_MS || "5000").trim()) || 5000);

type AgentSnapshot = {
  connected: boolean;
  printerName: string | null;
  printerId: string | null;
  selectedPrinterId: string | null;
  selectedPrinterName: string | null;
  deviceName: string;
  agentVersion: string;
  error: string | null;
  agentId: string;
  deviceFingerprint: string;
  capabilitySummary: ReturnType<typeof buildCapabilitySummary>;
  printers: LocalAgentPrinter[];
  calibrationProfile: CalibrationProfile | null;
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

app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
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
  const fallbackSelectedId =
    state.selectedPrinterId && printers.some((printer) => printer.printerId === state.selectedPrinterId)
      ? state.selectedPrinterId
      : printers.find((printer) => printer.isDefault)?.printerId || printers[0]?.printerId || null;
  if (fallbackSelectedId !== state.selectedPrinterId) {
    state = {
      ...state,
      selectedPrinterId: fallbackSelectedId,
    };
    await saveAgentState(state);
  }

  const selectedPrinter =
    printers.find((printer) => printer.printerId === fallbackSelectedId) ||
    printers.find((printer) => printer.isDefault) ||
    printers[0] ||
    null;

  const connected = Boolean(selectedPrinter && selectedPrinter.online);
  const error =
    printers.length === 0
      ? inventory.error || "No printers detected by the local operating system."
      : !selectedPrinter
        ? "Select a printer before printing."
        : selectedPrinter.online
          ? null
          : `${selectedPrinter.printerName} is offline or paused.`;

  const snapshot: AgentSnapshot = {
    connected,
    printerName: selectedPrinter?.printerName || null,
    printerId: selectedPrinter?.printerId || null,
    selectedPrinterId: selectedPrinter?.printerId || null,
    selectedPrinterName: selectedPrinter?.printerName || null,
    deviceName: resolveDeviceName(),
    agentVersion: AGENT_VERSION,
    error,
    agentId: state.agentId,
    deviceFingerprint: state.deviceFingerprint,
    capabilitySummary: buildCapabilitySummary(printers, selectedPrinter?.printerId || null),
    printers,
    calibrationProfile: selectedPrinter ? state.calibrationProfiles[selectedPrinter.printerId] || null : null,
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

const requirePrinter = async (printerId: string | null | undefined) => {
  const { state, snapshot } = await buildSnapshot(true);
  const resolvedPrinterId = String(printerId || snapshot.selectedPrinterId || "").trim();
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

app.post("/print", async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim();
    const scanUrl = String(req.body?.scanUrl || "").trim();
    if (!code || !scanUrl) {
      return res.status(400).json({ success: false, error: "code and scanUrl are required" });
    }

    const printerId = String(req.body?.printerId || "").trim() || null;
    const { state, printer } = await requirePrinter(printerId);

    let nextState = state;
    if (req.body?.printerId && req.body.printerId !== state.selectedPrinterId) {
      nextState = {
        ...state,
        selectedPrinterId: printer.printerId,
      };
    }
    if (req.body?.calibrationProfile && typeof req.body.calibrationProfile === "object") {
      nextState = mergeCalibrationProfile(nextState, printer.printerId, req.body.calibrationProfile);
    }
    if (nextState !== state) {
      await saveAgentState(nextState);
      invalidateInventoryCache();
    }

    const result = await printLabel({
      printerId: printer.printerId,
      printerName: printer.printerName,
      printerLanguages: printer.languages,
      calibrationProfile: nextState.calibrationProfiles[printer.printerId] || null,
      request: {
        code,
        scanUrl,
        payloadType: req.body?.payloadType || null,
        payloadContent: req.body?.payloadContent || null,
        payloadHash: req.body?.payloadHash || null,
        previewLabel: req.body?.previewLabel || null,
        copies: Number(req.body?.copies || 1) || 1,
        printPath: req.body?.printPath || null,
        labelLanguage: req.body?.labelLanguage || null,
        mediaSize: req.body?.mediaSize || null,
      },
    });

    return res.json({
      success: true,
      queued: true,
      printerName: result.printerName,
      jobRef: result.jobRef,
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
    });
  } catch (error: any) {
    return res.status(error?.statusCode || 500).json({
      success: false,
      error: error?.message || "Local print failed.",
    });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`MSCQR local print agent listening on http://${HOST}:${PORT}`);
});
