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

    const supportLink = screen.getAllByRole("link", { name: "Support" })[0];

    expect(supportLink).toHaveAttribute("href", "/help/support");
    expect(screen.getAllByRole("link", { name: /verify/i })[0]).toHaveAttribute("href", "/verify");
    expect(screen.getAllByRole("link", { name: /platform access/i })[0]).toHaveAttribute("href", "/login");
    expect(screen.getByRole("link", { name: /trust center/i })).toBeInTheDocument();
  });
});
