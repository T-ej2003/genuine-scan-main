import { LOCAL_AGENT_NO_WORK_RETRY_MS } from "./localAgentClaimService";
import {
  CONNECTOR_UPDATE_REQUIRED_CODE,
  CONNECTOR_UPDATE_REQUIRED_MESSAGE,
  getMissingTransportDiagnosticsCapabilities,
  isLocalAgentPersistentSessionCapable,
  isLocalAgentTransportDiagnosticsCurrent,
  isPersistentPrintSessionRequiredForProduction,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
  PRINTER_SESSION_REQUIRED_CODE,
  PRINTER_SESSION_REQUIRED_MESSAGE,
} from "./localAgentProtocol";

export const LOCAL_AGENT_UPGRADE_RETRY_MS = Math.max(60_000, LOCAL_AGENT_NO_WORK_RETRY_MS);

type LocalAgentClaimRuntimeData = {
  agentVersion?: string | null;
  buildVersion?: string | null;
  protocolVersion?: string | null;
  transportDiagnosticsVersion?: string | null;
  capabilities?: unknown;
};

type LocalAgentRegistrationLike = {
  id: string;
  agentId: string;
};

const toCapabilitiesRecord = (value: unknown): Record<string, unknown> | null => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
};

export const buildLocalAgentClaimRuntimeBlock = (
  data: LocalAgentClaimRuntimeData,
  registration: LocalAgentRegistrationLike
) => {
  const connectorVersion = data.agentVersion || data.buildVersion || null;
  if (isPersistentPrintSessionRequiredForProduction() && !isLocalAgentPersistentSessionCapable(connectorVersion)) {
    return {
      status: 426,
      log: {
        event: "connector_update_required",
        registrationId: registration.id,
        agentId: registration.agentId,
        reportedVersion: connectorVersion,
        requiredVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
      },
      payload: {
        success: false,
        error: CONNECTOR_UPDATE_REQUIRED_MESSAGE,
        code: CONNECTOR_UPDATE_REQUIRED_CODE,
        errorCode: CONNECTOR_UPDATE_REQUIRED_CODE,
        retryAfterMs: LOCAL_AGENT_UPGRADE_RETRY_MS,
        upgradeRequired: true,
        requiredVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
        expectedBuildVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
      },
    };
  }

  const capabilities = toCapabilitiesRecord(data.capabilities);
  const connectorCurrent = isLocalAgentTransportDiagnosticsCurrent({
    protocolVersion: data.protocolVersion || null,
    buildVersion: data.buildVersion || null,
    transportDiagnosticsVersion: data.transportDiagnosticsVersion || null,
    capabilities,
  });
  if (!connectorCurrent) {
    const missingCapabilities = getMissingTransportDiagnosticsCapabilities(capabilities);
    return {
      status: 426,
      log: {
        event: "connector_update_required",
        registrationId: registration.id,
        agentId: registration.agentId,
        agentVersion: data.agentVersion || null,
        buildVersion: data.buildVersion || null,
        protocolVersion: data.protocolVersion || null,
        transportDiagnosticsVersion: data.transportDiagnosticsVersion || null,
        missingCapabilities,
        expectedProtocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
        expectedBuildVersion: LOCAL_AGENT_MIN_VERSION_HINT,
        expectedTransportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
        retryAfterMs: LOCAL_AGENT_UPGRADE_RETRY_MS,
      },
      payload: {
        success: false,
        error: CONNECTOR_UPDATE_REQUIRED_MESSAGE,
        code: CONNECTOR_UPDATE_REQUIRED_CODE,
        errorCode: CONNECTOR_UPDATE_REQUIRED_CODE,
        retryAfterMs: LOCAL_AGENT_UPGRADE_RETRY_MS,
        upgradeRequired: true,
        requiredVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
        expectedProtocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
        expectedBuildVersion: LOCAL_AGENT_MIN_VERSION_HINT,
        expectedTransportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
        missingCapabilities,
      },
    };
  }

  if (isPersistentPrintSessionRequiredForProduction()) {
    return {
      status: 409,
      log: {
        event: "printer_session_required",
        registrationId: registration.id,
        agentId: registration.agentId,
        reportedVersion: connectorVersion,
      },
      payload: {
        success: false,
        error: PRINTER_SESSION_REQUIRED_MESSAGE,
        code: PRINTER_SESSION_REQUIRED_CODE,
        errorCode: PRINTER_SESSION_REQUIRED_CODE,
        retryAfterMs: LOCAL_AGENT_UPGRADE_RETRY_MS,
      },
    };
  }

  return null;
};
