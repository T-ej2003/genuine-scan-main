import { describe, expect, it } from "vitest";

import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";

describe("secure printer readiness", () => {
  it("shows an actionable persistent-session connector update state", () => {
    const readiness = buildSecurePrintReadiness({
      connected: true,
      trusted: false,
      eligibleForPrinting: false,
      stale: false,
      compatibilityMode: false,
      connectionClass: "BLOCKED",
      buildVersion: "2026.6.16",
      persistentSessionRequired: true,
      persistentSessionCapable: false,
      persistentSessionMinimumBuildVersion: "2026.6.25",
      persistentSessionUpdateRequired: true,
    });

    expect(readiness.ready).toBe(false);
    expect(readiness.reasonCode).toBe("CONNECTOR_UPDATE_REQUIRED");
    expect(readiness.summary).toBe("MSCQR Connector update required.");
    expect(readiness.detail).toContain("Update MSCQR Connector to use persistent print session mode.");
    expect(readiness.detail).toContain("Required 2026.6.25");
    expect(readiness.detail).toContain("detected 2026.6.16");
    expect(readiness.detail).not.toContain("Refresh printer helper before starting this print run");
  });
});
