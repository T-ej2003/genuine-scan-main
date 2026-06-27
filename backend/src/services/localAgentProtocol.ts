import { LOCAL_PRINT_AGENT_SOURCE_BUILD_VERSION } from "../local-print-agent/version";

export const LOCAL_AGENT_DIRECT_PROTOCOL_VERSION = "local-agent-direct-v2";
export const LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION = "2026.6.16";
export const LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION = LOCAL_PRINT_AGENT_SOURCE_BUILD_VERSION;
export const LOCAL_AGENT_MIN_VERSION_HINT = LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION;
export const LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION = "transport-diagnostics-v1";
export const CONNECTOR_UPDATE_REQUIRED_CODE = "CONNECTOR_UPDATE_REQUIRED";
export const CONNECTOR_UPDATE_REQUIRED_MESSAGE =
  "Update MSCQR Connector to use persistent print session mode.";
export const CONNECTOR_PERSISTENT_SESSION_UPDATE_REQUIRED_MESSAGE =
  "Update MSCQR Connector to use persistent print session mode.";
export const PRINTER_SESSION_REQUIRED_CODE = "PRINTER_SESSION_REQUIRED";
export const PRINTER_SESSION_REQUIRED_MESSAGE =
  "Persistent printer session is required for production printing.";
export const PRINTER_SESSION_DISCONNECTED_CODE = "PRINTER_SESSION_DISCONNECTED";
export const PRINTER_SESSION_DISCONNECTED_MESSAGE =
  "Persistent printer session is disconnected.";

export const getPrintAgentSessionMode = () => {
  const mode = String(process.env.PRINT_AGENT_SESSION_MODE || "websocket").trim().toLowerCase();
  return mode === "rest" || mode === "polling" ? mode : "websocket";
};

export const isPersistentPrintSessionRequiredForProduction = () => true;

export const LOCAL_AGENT_CAPABILITIES = {
  supportsPrinterQueueSnapshot: true,
  supportsWindowsTcpPortInspection: true,
  supportsRawTcpConnectTest: true,
  supportsRawTcpZplSend: true,
  supportsUsbRawSpooler: true,
  supportsSpoolJobCancel: true,
  supportsSpoolJobStatus: true,
  supportsTransportDiagnostics: true,
  supportsTestLabel: true,
  supportsPersistentPrintSession: true,
  supportsOfficialMscqrZplWordmark: true,
} as const;

export const REQUIRED_LOCAL_AGENT_CAPABILITY_FLAGS = Object.keys(LOCAL_AGENT_CAPABILITIES) as Array<
  keyof typeof LOCAL_AGENT_CAPABILITIES
>;
const REST_FALLBACK_CAPABILITY_FLAGS = REQUIRED_LOCAL_AGENT_CAPABILITY_FLAGS.filter(
  (flag) => flag !== "supportsPersistentPrintSession"
);

export const isLocalAgentProtocolCompatible = (protocolVersion?: string | null) =>
  String(protocolVersion || "").trim() === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION;

const parseVersionParts = (value?: string | null) =>
  String(value || "")
    .trim()
    .split(/[.-]/)
    .map((part) => Number.parseInt(part, 10))
    .filter((part) => Number.isFinite(part));

export const compareLocalAgentVersions = (left?: string | null, right?: string | null) => {
  const a = parseVersionParts(left);
  const b = parseVersionParts(right);
  const length = Math.max(a.length, b.length, 3);
  for (let index = 0; index < length; index += 1) {
    const delta = (a[index] || 0) - (b[index] || 0);
    if (delta !== 0) return delta;
  }
  return 0;
};

export const isLocalAgentBuildAtLeast = (buildVersion?: string | null, minimum = LOCAL_AGENT_MIN_VERSION_HINT) =>
  compareLocalAgentVersions(buildVersion, minimum) >= 0;

export const isLocalAgentPersistentSessionCapable = (buildVersion?: string | null) =>
  isLocalAgentBuildAtLeast(buildVersion, LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION);

export const getMissingTransportDiagnosticsCapabilities = (capabilities?: Record<string, unknown> | null) =>
  REST_FALLBACK_CAPABILITY_FLAGS.filter((flag) => capabilities?.[flag] !== true);

export const hasRequiredTransportDiagnosticsCapabilities = (capabilities?: Record<string, unknown> | null) =>
  Boolean(capabilities && getMissingTransportDiagnosticsCapabilities(capabilities).length === 0);

export const isLocalAgentTransportDiagnosticsCurrent = (input: {
  protocolVersion?: string | null;
  buildVersion?: string | null;
  transportDiagnosticsVersion?: string | null;
  capabilities?: Record<string, unknown> | null;
}) =>
  isLocalAgentProtocolCompatible(input.protocolVersion) &&
  isLocalAgentBuildAtLeast(input.buildVersion, LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION) &&
  input.transportDiagnosticsVersion === LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION &&
  hasRequiredTransportDiagnosticsCapabilities(input.capabilities);
