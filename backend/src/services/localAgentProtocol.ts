import { LOCAL_PRINT_AGENT_SOURCE_BUILD_VERSION } from "../local-print-agent/version";

export const LOCAL_AGENT_DIRECT_PROTOCOL_VERSION = "local-agent-direct-v2";
export const LOCAL_AGENT_MIN_VERSION_HINT = LOCAL_PRINT_AGENT_SOURCE_BUILD_VERSION;
export const CONNECTOR_UPDATE_REQUIRED_CODE = "connector_update_required";
export const CONNECTOR_UPDATE_REQUIRED_MESSAGE =
  "MSCQR Connector must be updated before it can claim print jobs.";

export const isLocalAgentProtocolCompatible = (protocolVersion?: string | null) =>
  String(protocolVersion || "").trim() === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION;
