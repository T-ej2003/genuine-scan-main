import { execFile } from "child_process";
import os from "os";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export type LocalAgentPrinter = {
  printerId: string;
  printerName: string;
  model: string | null;
  connection: string | null;
  online: boolean;
  isDefault: boolean;
  protocols: string[];
  languages: string[];
  mediaSizes: string[];
  dpi: number | null;
  deviceUri?: string | null;
  portName?: string | null;
};

export type LocalAgentCapabilitySummary = {
  transports: string[];
  protocols: string[];
  languages: string[];
  supportsRaster: boolean;
  supportsPdf: boolean;
  dpiOptions: number[];
  mediaSizes: string[];
};

export type LocalAgentPrinterSelectionSource =
  | "persisted"
  | "default"
  | "first_online"
  | "first_available"
  | "none";

export type LocalAgentPrinterSelection = {
  printer: LocalAgentPrinter | null;
  printerId: string | null;
  printerName: string | null;
  selectionSource: LocalAgentPrinterSelectionSource;
};

export type LocalAgentSetupVerificationState = "READY" | "NO_PRINTERS" | "PRINTER_UNAVAILABLE";

export type LocalAgentSetupVerification = {
  state: LocalAgentSetupVerificationState;
  success: boolean;
  message: string;
  printerCount: number;
  onlinePrinterCount: number;
  selectedPrinterId: string | null;
  selectedPrinterName: string | null;
  selectionSource: LocalAgentPrinterSelectionSource;
};

type ParsedSystemProfilerPrinter = {
  name: string;
  model: string | null;
  uri: string | null;
  printerCommands: string[];
  status: string | null;
  isDefault: boolean;
};

type ParsedLpoptions = {
  mediaSizes: string[];
  dpiOptions: number[];
};

type ParsedWindowsPrinter = {
  name: string;
  driverName: string | null;
  portName: string | null;
  online: boolean;
  isDefault: boolean;
};

const COMMAND_TIMEOUT_MS = 1500;
const MAX_BUFFER = 1024 * 1024 * 2;

const toCleanString = (value: unknown, max = 180) => String(value || "").trim().slice(0, max);

const uniqueStrings = (values: Array<string | null | undefined>, maxItems = 24) => {
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = toCleanString(value, 120);
    if (!normalized) continue;
    seen.add(normalized);
    if (seen.size >= maxItems) break;
  }
  return Array.from(seen);
};

const normalizePrinterKey = (value: string) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

const maybeExecFile = async (file: string, args: string[]) => {
  try {
    return await execFileAsync(file, args, {
      timeout: COMMAND_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
  } catch (error: any) {
    if (error?.code === "ENOENT") return { stdout: "", stderr: "" };
    if (error?.killed || error?.signal === "SIGTERM") return { stdout: "", stderr: "" };
    throw error;
  }
};

export const parseLpstatPrinters = (stdout: string) => {
  const rows: Array<{ printerId: string; online: boolean }> = [];
  for (const rawLine of String(stdout || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = line.match(/^printer\s+(\S+)\s+(.*)$/i);
    if (!match) continue;
    const printerId = match[1];
    const statusText = match[2].toLowerCase();
    const online =
      !statusText.includes("disabled") &&
      !statusText.includes("offline") &&
      !statusText.includes("paused");
    rows.push({ printerId, online });
  }
  return rows;
};

export const parseDefaultPrinter = (stdout: string) => {
  const match = String(stdout || "").match(/system default destination:\s*(\S+)/i);
  return match?.[1] || null;
};

export const parseLpstatUris = (stdout: string) => {
  const byId = new Map<string, string>();
  for (const rawLine of String(stdout || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = line.match(/^device for\s+(\S+):\s+(.+)$/i);
    if (!match) continue;
    byId.set(match[1], match[2].trim());
  }
  return byId;
};

export const parseLpoptionsDetails = (stdout: string): ParsedLpoptions => {
  const mediaSizes = new Set<string>();
  const dpiOptions = new Set<number>();

  for (const rawLine of String(stdout || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    if (/^PageSize\/|^media\/|^MediaSize\//i.test(line)) {
      const [, rawValues = ""] = line.split(":", 2);
      for (const token of rawValues.split(/\s+/)) {
        const normalized = token.replace(/^\*/, "").trim();
        if (!normalized) continue;
        mediaSizes.add(normalized);
      }
    }

    if (/dpi|resolution/i.test(line)) {
      for (const match of line.matchAll(/(\d{2,4})dpi|(\d{2,4})/gi)) {
        const value = Number(match[1] || match[2] || 0);
        if (Number.isFinite(value) && value >= 72 && value <= 2400) {
          dpiOptions.add(value);
        }
      }
    }
  }

  return {
    mediaSizes: Array.from(mediaSizes).slice(0, 24),
    dpiOptions: Array.from(dpiOptions).sort((a, b) => a - b).slice(0, 12),
  };
};

export const parseSystemProfilerPrinters = (stdout: string): ParsedSystemProfilerPrinter[] => {
  const payload = JSON.parse(String(stdout || "{}"));
  const rows = Array.isArray(payload?.SPPrintersDataType) ? payload.SPPrintersDataType : [];
  const printers: ParsedSystemProfilerPrinter[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") continue;
    const printerCommands = String((raw as any).printercommands || "")
      .split(/[,\s]+/)
      .map((value) => value.trim().toUpperCase())
      .filter(Boolean)
      .filter((value) => value !== "NONE");
    printers.push({
      name: toCleanString((raw as any)._name || (raw as any).name),
      model: toCleanString((raw as any).ppd || (raw as any).model) || null,
      uri: toCleanString((raw as any).uri, 512) || null,
      printerCommands,
      status: toCleanString((raw as any).status, 80) || null,
      isDefault: String((raw as any).default || "").trim().toLowerCase() === "yes",
    });
  }
  return printers;
};

export const parseWindowsPrinters = (stdout: string): ParsedWindowsPrinter[] => {
  const raw = JSON.parse(String(stdout || "[]"));
  const rows = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const printers: ParsedWindowsPrinter[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const name = toCleanString((row as any).Name || (row as any).name);
    if (!name) continue;
    const workOffline = Boolean((row as any).WorkOffline);
    const printerStatus = Number((row as any).PrinterStatus);
    const extendedStatus = Number((row as any).ExtendedPrinterStatus);
    const online = !workOffline && ![7].includes(printerStatus) && ![7].includes(extendedStatus);
    printers.push({
      name,
      driverName: toCleanString((row as any).DriverName || (row as any).driverName) || null,
      portName: toCleanString((row as any).PortName || (row as any).portName, 180) || null,
      online,
      isDefault: Boolean((row as any).Default),
    });
  }
  return printers;
};

const inferProtocols = (uri: string | null) => {
  const normalized = toCleanString(uri, 512).toLowerCase();
  const values: string[] = [];
  if (!normalized) return values;
  if (normalized.startsWith("usb://")) values.push("usb");
  if (normalized.startsWith("socket://")) values.push("raw-9100");
  if (normalized.startsWith("ipp://")) values.push("ipp");
  if (normalized.startsWith("ipps://")) values.push("ipps");
  if (normalized.startsWith("dnssd://")) values.push("dnssd");
  if (normalized.includes("_ipps._tcp")) values.push("ipps");
  if (normalized.includes("_ipp._tcp")) values.push("ipp");
  return uniqueStrings(values, 8);
};

const inferConnection = (uri: string | null) => {
  const normalized = toCleanString(uri, 512).toLowerCase();
  if (!normalized) return "spooler";
  if (normalized.startsWith("usb://")) return "usb";
  if (normalized.startsWith("socket://")) return "network";
  if (normalized.startsWith("ipps://") || normalized.includes("_ipps._tcp")) return "ipps";
  if (normalized.startsWith("ipp://") || normalized.includes("_ipp._tcp")) return "ipp";
  if (normalized.startsWith("dnssd://")) return "bonjour";
  return "spooler";
};

const inferFriendlyName = (printerId: string, profiler: ParsedSystemProfilerPrinter | null) => {
  if (profiler?.name) return profiler.name;
  return printerId.replace(/_/g, " ");
};

const inferLanguages = (profiler: ParsedSystemProfilerPrinter | null) => {
  const values = profiler?.printerCommands || [];
  const known = values.filter((value) =>
    ["ZPL", "TSPL", "SBPL", "EPL", "CPCL", "ESC_POS", "ESC/POS"].includes(value)
  );
  return uniqueStrings(
    known.map((value) => (value === "ESC/POS" ? "ESC_POS" : value)),
    8
  );
};

const inferWindowsConnection = (portName: string | null) => {
  const normalized = toCleanString(portName, 180).toUpperCase();
  if (!normalized) return "spooler";
  if (normalized.startsWith("USB")) return "usb";
  if (normalized.startsWith("WSD")) return "network";
  if (normalized.startsWith("IP_")) return "network";
  if (normalized.includes("IPP")) return "ipp";
  if (normalized.includes("IPPS")) return "ipps";
  if (normalized.startsWith("\\\\")) return "shared";
  return "spooler";
};

const inferWindowsProtocols = (portName: string | null) => {
  const normalized = toCleanString(portName, 180).toUpperCase();
  const protocols: string[] = [];
  if (!normalized) return protocols;
  if (normalized.startsWith("USB")) protocols.push("usb");
  if (normalized.startsWith("WSD")) protocols.push("wsd");
  if (normalized.startsWith("IP_")) protocols.push("tcp");
  if (normalized.includes("IPP")) protocols.push("ipp");
  if (normalized.includes("IPPS")) protocols.push("ipps");
  if (normalized.startsWith("\\\\")) protocols.push("shared");
  return uniqueStrings(protocols, 8);
};

const inferWindowsLanguages = (driverName: string | null, printerName: string) => {
  const combined = `${driverName || ""} ${printerName}`.toUpperCase();
  const languages: string[] = [];
  if (combined.includes("ZPL")) languages.push("ZPL");
  if (combined.includes("TSPL")) languages.push("TSPL");
  if (combined.includes("SBPL") || combined.includes("SATO")) languages.push("SBPL");
  if (combined.includes("EPL")) languages.push("EPL");
  if (combined.includes("CPCL")) languages.push("CPCL");
  if (combined.includes("ESC/POS") || combined.includes("ESC_POS") || combined.includes("RECEIPT")) languages.push("ESC_POS");
  return uniqueStrings(languages, 8);
};

export const buildCapabilitySummary = (
  printers: LocalAgentPrinter[],
  selectedPrinterId: string | null
): LocalAgentCapabilitySummary | null => {
  const selected =
    printers.find((printer) => printer.printerId === selectedPrinterId) ||
    printers.find((printer) => printer.isDefault) ||
    printers[0];
  if (!selected) return null;

  return {
    transports: uniqueStrings([selected.connection, "spooler", "pdf-raster"], 6),
    protocols: uniqueStrings(selected.protocols, 12),
    languages: uniqueStrings(selected.languages.length > 0 ? selected.languages : ["AUTO"], 12),
    supportsRaster: true,
    supportsPdf: true,
    dpiOptions: selected.dpi ? [selected.dpi] : [300],
    mediaSizes: selected.mediaSizes.slice(0, 12),
  };
};

export const resolveSelectedPrinter = (
  printers: LocalAgentPrinter[],
  persistedSelectedPrinterId: string | null
): LocalAgentPrinterSelection => {
  if (printers.length === 0) {
    return {
      printer: null,
      printerId: null,
      printerName: null,
      selectionSource: "none",
    };
  }

  const persisted =
    persistedSelectedPrinterId
      ? printers.find((printer) => printer.printerId === persistedSelectedPrinterId) || null
      : null;
  if (persisted) {
    return {
      printer: persisted,
      printerId: persisted.printerId,
      printerName: persisted.printerName,
      selectionSource: "persisted",
    };
  }

  const defaultPrinter = printers.find((printer) => printer.isDefault) || null;
  const firstOnline = printers.find((printer) => printer.online) || null;

  if (defaultPrinter?.online) {
    return {
      printer: defaultPrinter,
      printerId: defaultPrinter.printerId,
      printerName: defaultPrinter.printerName,
      selectionSource: "default",
    };
  }

  if (firstOnline) {
    return {
      printer: firstOnline,
      printerId: firstOnline.printerId,
      printerName: firstOnline.printerName,
      selectionSource: "first_online",
    };
  }

  if (defaultPrinter) {
    return {
      printer: defaultPrinter,
      printerId: defaultPrinter.printerId,
      printerName: defaultPrinter.printerName,
      selectionSource: "default",
    };
  }

  const firstAvailable = printers[0] || null;
  return {
    printer: firstAvailable,
    printerId: firstAvailable?.printerId || null,
    printerName: firstAvailable?.printerName || null,
    selectionSource: firstAvailable ? "first_available" : "none",
  };
};

export const buildSetupVerification = (params: {
  printers: LocalAgentPrinter[];
  selection: LocalAgentPrinterSelection;
  connected: boolean;
  inventoryError?: string | null;
}): LocalAgentSetupVerification => {
  const printerCount = params.printers.length;
  const onlinePrinterCount = params.printers.filter((printer) => printer.online).length;

  if (printerCount === 0) {
    return {
      state: "NO_PRINTERS",
      success: false,
      message: params.inventoryError || "Windows did not report any printers yet.",
      printerCount,
      onlinePrinterCount,
      selectedPrinterId: null,
      selectedPrinterName: null,
      selectionSource: "none",
    };
  }

  if (params.selection.printer && params.selection.printer.online && params.connected) {
    return {
      state: "READY",
      success: true,
      message: `${params.selection.printer.printerName} is installed, reachable, and ready to print.`,
      printerCount,
      onlinePrinterCount,
      selectedPrinterId: params.selection.printer.printerId,
      selectedPrinterName: params.selection.printer.printerName,
      selectionSource: params.selection.selectionSource,
    };
  }

  const message = params.selection.printer
    ? `${params.selection.printer.printerName} is installed, but Windows is not exposing it as an online printer yet.`
    : "Printers were detected, but MSCQR could not resolve a usable printer yet.";

  return {
    state: "PRINTER_UNAVAILABLE",
    success: false,
    message,
    printerCount,
    onlinePrinterCount,
    selectedPrinterId: params.selection.printerId,
    selectedPrinterName: params.selection.printerName,
    selectionSource: params.selection.selectionSource,
  };
};

export const listLocalPrinters = async (): Promise<{
  printers: LocalAgentPrinter[];
  error: string | null;
}> => {
  if (process.platform === "win32") {
    const script = [
      "$ErrorActionPreference='Stop'",
      "$printers = Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,WorkOffline,Default,PrinterStatus,ExtendedPrinterStatus",
      "$printers | ConvertTo-Json -Compress",
    ].join("; ");
    const result = await maybeExecFile("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      script,
    ]);

    let rows: ParsedWindowsPrinter[] = [];
    try {
      rows = result.stdout ? parseWindowsPrinters(result.stdout) : [];
    } catch {
      rows = [];
    }

    const printers = rows
      .map((row) => ({
        printerId: row.name,
        printerName: row.name,
        model: row.driverName,
        connection: inferWindowsConnection(row.portName),
        online: row.online,
        isDefault: row.isDefault,
        protocols: inferWindowsProtocols(row.portName),
        languages: inferWindowsLanguages(row.driverName, row.name),
        mediaSizes: [],
        dpi: null,
        deviceUri: null,
        portName: row.portName,
      }))
      .sort((a, b) => {
        if (a.isDefault && !b.isDefault) return -1;
        if (!a.isDefault && b.isDefault) return 1;
        return a.printerName.localeCompare(b.printerName);
      });

    if (printers.length > 0) {
      return { printers, error: null };
    }

    const stderr = String(result.stderr || "").trim();
    return {
      printers: [],
      error: stderr || "No printers detected by the Windows print spooler.",
    };
  }

  const [lpstatPrintersRes, lpstatUrisRes, profilerRes] = await Promise.all([
    maybeExecFile("/usr/bin/lpstat", ["-p", "-d"]),
    maybeExecFile("/usr/bin/lpstat", ["-v"]),
    process.platform === "darwin"
      ? maybeExecFile("/usr/sbin/system_profiler", ["SPPrintersDataType", "-json"])
      : Promise.resolve({ stdout: "", stderr: "" }),
  ]);

  const basePrinters = parseLpstatPrinters(lpstatPrintersRes.stdout);
  const defaultPrinterId = parseDefaultPrinter(lpstatPrintersRes.stdout);
  const uriById = parseLpstatUris(lpstatUrisRes.stdout);

  let profilerRows: ParsedSystemProfilerPrinter[] = [];
  try {
    profilerRows = profilerRes.stdout ? parseSystemProfilerPrinters(profilerRes.stdout) : [];
  } catch {
    profilerRows = [];
  }

  const profilerById = new Map<string, ParsedSystemProfilerPrinter>();
  for (const row of profilerRows) {
    const key = normalizePrinterKey(row.name);
    if (key) profilerById.set(key, row);
  }

  const printers = await Promise.all(
    basePrinters.map(async (basePrinter) => {
      const optionsRes = await maybeExecFile("/usr/bin/lpoptions", ["-p", basePrinter.printerId, "-l"]);
      const parsedOptions = parseLpoptionsDetails(optionsRes.stdout);
      const profiler =
        profilerById.get(normalizePrinterKey(basePrinter.printerId)) ||
        profilerById.get(normalizePrinterKey(basePrinter.printerId.replace(/_/g, " "))) ||
        null;
      const uri = profiler?.uri || uriById.get(basePrinter.printerId) || null;
      const protocols = inferProtocols(uri);
      const model = profiler?.model || null;
      const online = profiler?.status ? profiler.status.toLowerCase() !== "offline" : basePrinter.online;
      return {
        printerId: basePrinter.printerId,
        printerName: inferFriendlyName(basePrinter.printerId, profiler),
        model,
        connection: inferConnection(uri),
        online,
        isDefault: Boolean(profiler?.isDefault || basePrinter.printerId === defaultPrinterId),
        protocols,
        languages: inferLanguages(profiler),
        mediaSizes: parsedOptions.mediaSizes,
        dpi: parsedOptions.dpiOptions.length > 0 ? parsedOptions.dpiOptions[parsedOptions.dpiOptions.length - 1] : null,
        deviceUri: uri,
        portName: null,
      } satisfies LocalAgentPrinter;
    })
  );

  const sorted = printers.sort((a, b) => {
    if (a.isDefault && !b.isDefault) return -1;
    if (!a.isDefault && b.isDefault) return 1;
    return a.printerName.localeCompare(b.printerName);
  });

  if (sorted.length > 0) {
    return { printers: sorted, error: null };
  }

  const stderr = [lpstatPrintersRes.stderr, lpstatUrisRes.stderr].map((value) => String(value || "").trim()).filter(Boolean).join(" ");
  const fallbackError =
    stderr ||
    (os.platform() === "darwin"
      ? "No printers detected by macOS CUPS."
      : "No printers detected by the local CUPS spooler.");
  return { printers: [], error: fallbackError };
};
