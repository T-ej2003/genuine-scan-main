import React from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
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

    const header = screen.getByRole("banner");
    const main = screen.getByRole("main");
    const headerNav = within(header).getByRole("navigation", { name: "Public MSCQR navigation" });
    const brandsLink = within(headerNav).getByRole("link", { name: "For Brands" });
    const manufacturersLink = within(headerNav).getByRole("link", { name: "For Manufacturers" });
    const scanningLink = within(headerNav).getByRole("link", { name: "How Scanning Works" });
    const aboutLink = within(headerNav).getByRole("link", { name: "About" });
    const contactLink = within(headerNav).getByRole("link", { name: "Contact" });

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
    expect(within(headerNav).getByRole("link", { name: "Trust & Security" })).toHaveAttribute("href", "/trust");
    expect(contactLink).toHaveAttribute("href", "/contact");
    expect(within(header).queryByRole("link", { name: "Request Access" })).not.toBeInTheDocument();
    expect(within(header).queryByRole("link", { name: /verify product/i })).not.toBeInTheDocument();
    expect(within(header).getByRole("link", { name: /sign in/i })).toHaveAttribute("href", "/login");
    expect(within(header).getByRole("button", { name: /open public navigation menu/i })).toBeInTheDocument();
    expect(within(main).getByRole("link", { name: "Request Access" })).toHaveAttribute("href", "/request-access");
    expect(within(main).getByRole("link", { name: /verify a product/i })).toHaveAttribute("href", "/verify");
  });
});
