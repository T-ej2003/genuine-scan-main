import React from "react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";

import PrivacyPolicy from "@/pages/PrivacyPolicy";
import CookieNotice from "@/pages/CookieNotice";
import TermsOfUse from "@/pages/TermsOfUse";
import NotFound from "@/pages/NotFound";

describe("launch legal and trust surface", () => {
  it("renders finalized public legal notices with coherent footer links", () => {
    render(
      <MemoryRouter>
        <>
          <PrivacyPolicy />
          <CookieNotice />
          <TermsOfUse />
        </>
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: /privacy notice/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /cookie notice/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /terms of use/i })).toBeInTheDocument();
    expect(screen.queryByText(/lawyer review required before public launch/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/review-required draft/i)).not.toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Privacy" })[0]).toHaveAttribute("href", "/privacy");
    expect(screen.getAllByRole("link", { name: "Terms" })[0]).toHaveAttribute("href", "/terms");
    expect(screen.getAllByRole("link", { name: "Cookies" })[0]).toHaveAttribute("href", "/cookies");
    expect(screen.getAllByRole("link", { name: /cookie notice/i })[0]).toHaveAttribute("href", "/cookies");
    expect(screen.getAllByRole("link", { name: /terms of use/i })[0]).toHaveAttribute("href", "/terms");
    expect(screen.getAllByRole("link", { name: /privacy notice/i })[0]).toHaveAttribute("href", "/privacy");
    expect(screen.getAllByText(/Version 1.0/i).length).toBeGreaterThanOrEqual(3);
  });

  it("renders the branded 404 recovery page with trusted entry points", () => {
    render(
      <MemoryRouter initialEntries={["/missing-page"]}>
        <NotFound />
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: /that page is not available/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /verify a product/i })).toHaveAttribute("href", "/verify");
    expect(screen.getByRole("link", { name: /open trust center/i })).toHaveAttribute("href", "/trust");
    expect(screen.getByRole("link", { name: /get help/i })).toHaveAttribute("href", "/help/support");
  });
});
