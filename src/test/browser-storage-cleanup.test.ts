import { describe, expect, it } from "vitest";

import {
  cleanupDangerousLegacyBrowserStorage,
  DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS,
} from "@/lib/browser-storage-cleanup";

describe("browser storage cleanup", () => {
  it("removes dangerous legacy localStorage keys without touching allowed workflow preferences", () => {
    window.localStorage.clear();

    for (const key of DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS) {
      window.localStorage.setItem(key, `legacy:${key}`);
    }
    window.localStorage.setItem("theme", "dark");
    window.localStorage.setItem("printer-calibration:Canon_TS4100i_series", JSON.stringify({ dpi: 300 }));
    window.localStorage.setItem("manufacturer-printer-onboarding:v1:user-1", "dismissed");

    const result = cleanupDangerousLegacyBrowserStorage();

    expect(result.removedLocalStorageKeys.sort()).toEqual([...DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS].sort());
    for (const key of DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS) {
      expect(window.localStorage.getItem(key)).toBeNull();
    }
    expect(window.localStorage.getItem("theme")).toBe("dark");
    expect(window.localStorage.getItem("printer-calibration:Canon_TS4100i_series")).toBe(JSON.stringify({ dpi: 300 }));
    expect(window.localStorage.getItem("manufacturer-printer-onboarding:v1:user-1")).toBe("dismissed");
  });

  it("does not fail when keys are already absent", () => {
    window.localStorage.clear();

    expect(cleanupDangerousLegacyBrowserStorage()).toEqual({ removedLocalStorageKeys: [] });
  });
});
