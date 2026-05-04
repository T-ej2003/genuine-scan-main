import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  cleanupNonEssentialBrowserState,
  CONSENT_CHANGED_EVENT,
  CONSENT_STORAGE_KEY,
  getOptionalLocalStorageItem,
  getOptionalSessionStorageItem,
  hasConsent,
  readConsentState,
  setEssentialOnlyConsent,
  setOptionalCookie,
  setOptionalLocalStorageItem,
  setOptionalSessionStorageItem,
  writeConsentState,
} from "@/lib/consent";

const LEGACY_CONSENT_STORAGE_KEY = "mscqr_cookie_consent_choice:v1";

const expireCookie = (name: string) => {
  document.cookie = `${name}=; Max-Age=0; Path=/`;
};

describe("browser consent enforcement", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    expireCookie("sidebar:state");
  });

  it("keeps strictly necessary consent enabled and optional categories fail-closed by default", () => {
    expect(hasConsent("strictly_necessary")).toBe(true);
    expect(hasConsent("functional")).toBe(false);
    expect(hasConsent("analytics")).toBe(false);
    expect(hasConsent("marketing")).toBe(false);
  });

  it("blocks non-essential browser storage before matching consent exists", () => {
    expect(setOptionalLocalStorageItem("functional", "theme", "dark")).toBe(false);
    expect(setOptionalSessionStorageItem("functional", "manufacturer-printer-dialog-opened:v1:user-1", "shown")).toBe(false);
    expect(setOptionalCookie("functional", "sidebar:state", "true", { path: "/" })).toBe(false);

    expect(window.localStorage.getItem("theme")).toBeNull();
    expect(getOptionalLocalStorageItem("functional", "theme")).toBeNull();
    expect(window.sessionStorage.getItem("manufacturer-printer-dialog-opened:v1:user-1")).toBeNull();
    expect(getOptionalSessionStorageItem("functional", "manufacturer-printer-dialog-opened:v1:user-1")).toBeNull();
    expect(document.cookie).not.toContain("sidebar:state=");
  });

  it("allows category-matched browser storage after consent is granted", () => {
    writeConsentState({ functional: true, analytics: false, marketing: false });

    expect(setOptionalLocalStorageItem("functional", "theme", "dark")).toBe(true);
    expect(setOptionalLocalStorageItem("functional", "printer-calibration:Canon_TS4100i_series", "{\"dpi\":300}")).toBe(true);
    expect(setOptionalSessionStorageItem("functional", "manufacturer-printer-dialog-opened:v1:user-1", "shown")).toBe(true);
    expect(setOptionalCookie("functional", "sidebar:state", "true", { path: "/" })).toBe(true);

    expect(getOptionalLocalStorageItem("functional", "theme")).toBe("dark");
    expect(window.localStorage.getItem("printer-calibration:Canon_TS4100i_series")).toBe("{\"dpi\":300}");
    expect(getOptionalSessionStorageItem("functional", "manufacturer-printer-dialog-opened:v1:user-1")).toBe("shown");
    expect(document.cookie).toContain("sidebar:state=true");
  });

  it("cleans functional storage and emits changes when consent is withdrawn", () => {
    const listener = vi.fn();
    window.addEventListener(CONSENT_CHANGED_EVENT, listener);

    writeConsentState({ functional: true, analytics: false, marketing: false });
    window.localStorage.setItem("theme", "dark");
    window.localStorage.setItem("aq_missing_help_requests", "[\"help-1\"]");
    window.localStorage.setItem("printer-calibration:Canon_TS4100i_series", "{\"dpi\":300}");
    window.localStorage.setItem("manufacturer-printer-onboarding:v1:user-1", "dismissed");
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:user-1", "shown");
    document.cookie = "sidebar:state=true; Path=/; SameSite=Lax";

    setEssentialOnlyConsent();

    expect(window.localStorage.getItem("theme")).toBeNull();
    expect(window.localStorage.getItem("aq_missing_help_requests")).toBeNull();
    expect(window.localStorage.getItem("printer-calibration:Canon_TS4100i_series")).toBeNull();
    expect(window.localStorage.getItem("manufacturer-printer-onboarding:v1:user-1")).toBeNull();
    expect(window.sessionStorage.getItem("manufacturer-printer-dialog-opened:v1:user-1")).toBeNull();
    expect(document.cookie).not.toContain("sidebar:state=");
    expect(listener).toHaveBeenCalled();

    window.removeEventListener(CONSENT_CHANGED_EVENT, listener);
  });

  it("migrates the old all-or-essential banner choice into the versioned consent model", () => {
    window.localStorage.setItem(LEGACY_CONSENT_STORAGE_KEY, "accepted");

    const state = readConsentState();

    expect(state.categories).toEqual({ functional: true, analytics: true, marketing: true });
    expect(window.localStorage.getItem(LEGACY_CONSENT_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(CONSENT_STORAGE_KEY)).toBeTruthy();
  });

  it("removes existing functional storage during app startup cleanup when consent is absent", () => {
    window.localStorage.setItem("theme", "dark");
    window.localStorage.setItem("printer-calibration:Canon_TS4100i_series", "{\"dpi\":300}");
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:user-1", "shown");
    document.cookie = "sidebar:state=true; Path=/; SameSite=Lax";

    cleanupNonEssentialBrowserState();

    expect(window.localStorage.getItem("theme")).toBeNull();
    expect(window.localStorage.getItem("printer-calibration:Canon_TS4100i_series")).toBeNull();
    expect(window.sessionStorage.getItem("manufacturer-printer-dialog-opened:v1:user-1")).toBeNull();
    expect(document.cookie).not.toContain("sidebar:state=");
  });
});
