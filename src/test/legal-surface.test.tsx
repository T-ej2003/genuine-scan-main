import React from "react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";

import PrivacyPolicy from "@/pages/PrivacyPolicy";
import NotFound from "@/pages/NotFound";

describe("launch legal and trust surface", () => {
  it("renders the privacy notice with review-required messaging and footer links", () => {
    render(
      <MemoryRouter>
        <PrivacyPolicy />
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { name: /privacy notice/i })).toBeInTheDocument();
    expect(screen.getByText(/lawyer review required before public launch/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "/privacy");
    expect(screen.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
    expect(screen.getByRole("link", { name: "Cookies" })).toHaveAttribute("href", "/cookies");
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
