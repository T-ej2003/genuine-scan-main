import { beforeEach, describe, expect, it, vi } from "vitest";

describe("frontend monitoring consent gate", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
    window.localStorage.clear();
  });

  it("does not initialize frontend Sentry until analytics consent is granted", async () => {
    const init = vi.fn();
    vi.doMock("@sentry/react", () => ({ init }));
    vi.stubEnv("VITE_SENTRY_DSN", "https://public@example.invalid/1");
    vi.stubEnv("VITE_SENTRY_SAMPLE_RATE", "1");

    const [{ initFrontendMonitoring }, { writeConsentState }] = await Promise.all([
      import("@/lib/observability/frontend-monitoring"),
      import("@/lib/consent"),
    ]);

    initFrontendMonitoring();
    expect(init).not.toHaveBeenCalled();

    writeConsentState({ functional: false, analytics: true, marketing: false });
    expect(init).toHaveBeenCalledTimes(1);
  });
});
