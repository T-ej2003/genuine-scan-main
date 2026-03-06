import React from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
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

  it("tracks the active section when a header pill is clicked", () => {
    render(
      <MemoryRouter>
        <Index />
      </MemoryRouter>
    );

    const supportButton = screen.getByRole("button", { name: "Support" });
    fireEvent.click(supportButton);

    expect(supportButton).toHaveAttribute("aria-current", "true");
    expect(screen.getByText("Viewing Support")).toBeInTheDocument();
  });
});
