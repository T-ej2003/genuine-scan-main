import React from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { CookieConsentBanner } from "@/components/trust/CookieConsentBanner";
import { LegalFooter } from "@/components/trust/LegalFooter";
import { CONSENT_STORAGE_KEY, readConsentState, writeConsentState } from "@/lib/consent";

const expireCookie = (name: string) => {
  document.cookie = `${name}=; Max-Age=0; Path=/`;
};

const renderConsentManager = () =>
  render(
    <MemoryRouter>
      <CookieConsentBanner />
    </MemoryRouter>,
  );

const renderConsentManagerWithFooter = () =>
  render(
    <MemoryRouter>
      <CookieConsentBanner />
      <LegalFooter />
    </MemoryRouter>,
  );

describe("cookie consent preferences UI", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    expireCookie("sidebar:state");
  });

  it("shows the first-visit banner when no consent choice is stored", () => {
    renderConsentManager();

    expect(screen.getByText(/MSCQR uses necessary cookies and similar technologies/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /accept all/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reject non-essential/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /manage preferences/i })).toBeInTheDocument();
  });

  it("accepts all optional categories", () => {
    renderConsentManager();

    fireEvent.click(screen.getByRole("button", { name: /accept all/i }));

    expect(readConsentState().categories).toEqual({ functional: true, analytics: true, marketing: true });
    expect(screen.queryByText(/MSCQR uses necessary cookies and similar technologies/i)).not.toBeInTheDocument();
  });

  it("rejects non-essential storage and cleans existing functional items", () => {
    window.localStorage.setItem("theme", "dark");
    window.localStorage.setItem("printer-calibration:Canon_TS4100i_series", "{\"dpi\":300}");
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:user-1", "shown");
    document.cookie = "sidebar:state=true; Path=/; SameSite=Lax";

    renderConsentManager();

    fireEvent.click(screen.getByRole("button", { name: /reject non-essential/i }));

    expect(readConsentState().categories).toEqual({ functional: false, analytics: false, marketing: false });
    expect(window.localStorage.getItem("theme")).toBeNull();
    expect(window.localStorage.getItem("printer-calibration:Canon_TS4100i_series")).toBeNull();
    expect(window.sessionStorage.getItem("manufacturer-printer-dialog-opened:v1:user-1")).toBeNull();
    expect(document.cookie).not.toContain("sidebar:state=");
  });

  it("saves granular preferences by category", () => {
    renderConsentManager();

    fireEvent.click(screen.getByRole("button", { name: /manage preferences/i }));
    fireEvent.click(screen.getByRole("switch", { name: /functional preferences consent/i }));
    fireEvent.click(screen.getByRole("button", { name: /save preferences/i }));

    expect(readConsentState().categories).toEqual({ functional: true, analytics: false, marketing: false });
    expect(window.localStorage.getItem(CONSENT_STORAGE_KEY)).toBeTruthy();
  });

  it("reopens preferences from the footer and respects withdrawal across reloads", () => {
    writeConsentState({ functional: true, analytics: true, marketing: false });
    window.localStorage.setItem("theme", "dark");

    const firstRender = renderConsentManagerWithFooter();
    fireEvent.click(screen.getByRole("button", { name: /cookie preferences/i }));

    const functionalSwitch = screen.getByRole("switch", { name: /functional preferences consent/i });
    expect(functionalSwitch).toHaveAttribute("data-state", "checked");

    fireEvent.click(functionalSwitch);
    fireEvent.click(screen.getByRole("button", { name: /save preferences/i }));

    expect(readConsentState().categories).toEqual({ functional: false, analytics: true, marketing: false });
    expect(window.localStorage.getItem("theme")).toBeNull();

    firstRender.unmount();
    renderConsentManager();

    expect(screen.queryByText(/MSCQR uses necessary cookies and similar technologies/i)).not.toBeInTheDocument();
  });
});
