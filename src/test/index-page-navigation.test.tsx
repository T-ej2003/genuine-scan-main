import React from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Index from "@/pages/Index";

describe("Index page navigation", () => {
  beforeEach(() => {
    class MockIntersectionObserver {
      observe() {}
      disconnect() {}
      unobserve() {}
    }

    Object.defineProperty(window, "IntersectionObserver", {
      writable: true,
      configurable: true,
      value: MockIntersectionObserver,
    });
  });

  it("renders production public navigation and CTAs", () => {
    render(
      <MemoryRouter>
        <Index />
      </MemoryRouter>
    );

    const brandsLink = screen.getAllByRole("link", { name: "For Brands" })[0];
    const manufacturersLink = screen.getAllByRole("link", { name: "For Manufacturers" })[0];
    const scanningLink = screen.getAllByRole("link", { name: "How Scanning Works" })[0];
    const aboutLink = screen.getAllByRole("link", { name: "About" })[0];
    const contactLink = screen.getAllByRole("link", { name: "Contact" })[0];

    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 1, name: "MSCQR" })).toBeInTheDocument();
    expect(
      screen.getByText("A production authentication platform for QR-labelled products", {
        exact: false,
      }),
    ).toBeInTheDocument();
    expect(aboutLink).toHaveAttribute("href", "/about");
    expect(brandsLink).toHaveAttribute("href", "/solutions/brands");
    expect(manufacturersLink).toHaveAttribute("href", "/solutions/garment-manufacturers");
    expect(scanningLink).toHaveAttribute("href", "/how-scanning-works");
    expect(screen.getAllByRole("link", { name: /verify product/i })[0]).toHaveAttribute("href", "/verify");
    expect(screen.getAllByRole("link", { name: "Request Access" })[0]).toHaveAttribute("href", "/request-access");
    expect(screen.getAllByRole("link", { name: "Trust & Security" })[0]).toHaveAttribute("href", "/trust");
    expect(contactLink).toHaveAttribute("href", "/contact");
  });
});
