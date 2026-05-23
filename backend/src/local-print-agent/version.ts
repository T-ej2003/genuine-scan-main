export const LOCAL_PRINT_AGENT_SOURCE_VERSION = "2026.5.23";
export const LOCAL_PRINT_AGENT_SOURCE_BUILD_VERSION = LOCAL_PRINT_AGENT_SOURCE_VERSION;

const normalizeVersionOverride = (value?: string | null) => String(value || "").trim();

export const resolveLocalPrintAgentVersion = (override?: string | null) =>
  normalizeVersionOverride(override) || LOCAL_PRINT_AGENT_SOURCE_VERSION;

export const resolveLocalPrintAgentBuildVersion = (
  versionOverride?: string | null,
  buildVersionOverride?: string | null
) => {
  const version = resolveLocalPrintAgentVersion(versionOverride);
  return normalizeVersionOverride(buildVersionOverride) || version;
};
