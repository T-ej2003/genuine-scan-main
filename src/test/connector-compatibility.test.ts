import { describe, expect, it } from "vitest";
import { evaluateConnectorCompatibility } from "@/features/connector/connectorCompatibility";

const base = {
  reachable: true,
  installerAvailable: true,
  buildVersion: "2026.11.6.1",
  protocolVersion: "local-agent-direct-v2",
  requiredProtocol: "local-agent-direct-v2",
  minimumBuildVersion: "2026.11.6.1",
  latestVersion: "2026.11.6.2",
  installationScope: "fresh-install-only" as const,
};

describe("connector compatibility and installation matrix", () => {
  it.each([
    ["A no connector", { reachable: false }, "unknown", null, true],
    ["B fresh Windows installation", { reachable: false, buildVersion: null }, "unknown", null, true],
    ["C installed below minimum", { buildVersion: "2026.10.29.1" }, "unsupported", true, false],
    ["D installed at minimum", {}, "supported", false, false],
    ["E installed above minimum", { buildVersion: "2026.11.6.3" }, "supported", false, false],
    ["F below latest but supported", {}, "supported", false, false],
    ["G incompatible protocol", { protocolVersion: "local-agent-direct-v1" }, "unsupported", true, false],
    ["H missing build", { buildVersion: null }, "unknown", null, false],
    ["I missing protocol", { protocolVersion: null }, "unknown", null, false],
    ["J missing minimum", { minimumBuildVersion: null }, "unknown", null, false],
    ["K historical missing scope", { installationScope: null }, "supported", false, true],
    ["L fresh only latest", {}, "supported", false, false],
    ["M upgrade certified latest", { installationScope: null }, "supported", false, true],
    ["N unreachable connector", { reachable: false, buildVersion: null }, "unknown", null, true],
    ["O backend session rejected", { backendUpdateRequired: true }, "unsupported", true, false],
    ["P backend CONNECTOR_UPDATE_REQUIRED", { backendUpdateRequired: true }, "unsupported", true, false],
    ["Q backend minimum beyond latest", { minimumBuildVersion: "2026.11.6.3", installationScope: null }, "unsupported", true, false],
    ["Q unavailable even on disconnected workstation", { reachable: false, buildVersion: null, minimumBuildVersion: "2026.11.6.3", installationScope: null }, "unknown", null, false],
    ["Q unpublished signed package", { installerAvailable: false, installationScope: null }, "supported", false, false],
    ["R malformed build", { buildVersion: "2026.11.bad" }, "unknown", null, false],
    ["R unrecognized release scope", { installationScope: "unsupported-scope" }, "supported", null, false],
    ["S stale metadata cannot override backend", { backendUpdateRequired: true, minimumBuildVersion: "2026.5.1" }, "unsupported", true, false],
    ["T manufacturer existing install", { buildVersion: "2026.10.29.1" }, "unsupported", true, false],
    ["U numeric segment ordering", { buildVersion: "2026.9.30", minimumBuildVersion: "2026.10.1" }, "unsupported", true, false],
    ["U harmless whitespace", { buildVersion: " 2026.11.6.1 " }, "supported", false, false],
    ["V backend and frontend disagree", { backendUpdateRequired: true, buildVersion: "2026.11.6.2" }, "unsupported", true, false],
  ] as const)("%s", (_name, change, status, updateRequired, offerInstaller) => {
    expect(evaluateConnectorCompatibility({ ...base, ...change })).toMatchObject({ status, updateRequired, offerInstaller });
  });

  it("does not offer an older upgrade installer that cannot satisfy the backend minimum", () => {
    expect(evaluateConnectorCompatibility({ ...base, installationScope: null, buildVersion: "2026.10.29.1", minimumBuildVersion: "2026.11.6.3" }))
      .toMatchObject({ status: "unsupported", updateRequired: true, offerInstaller: false, maintenanceRequired: true });
  });

  it("separates an optional certified upgrade from a required compatibility update", () => {
    expect(evaluateConnectorCompatibility({ ...base, installationScope: null }))
      .toMatchObject({ status: "supported", updateRequired: false, updateAvailable: true, offerInstaller: true });
  });
});
