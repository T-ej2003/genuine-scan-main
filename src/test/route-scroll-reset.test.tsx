import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Link, MemoryRouter, Route, Routes } from "react-router";

import { RouteScrollReset } from "@/components/RouteScrollReset";

function TestRouter() {
  return (
    <>
      <RouteScrollReset />
      <nav>
        <Link to="/manufacturers">Manufacturers</Link>
        <Link to="/batches#details">Batches details</Link>
      </nav>
      <Routes>
        <Route path="/audit-history" element={<div>History</div>} />
        <Route path="/manufacturers" element={<div>Manufacturers</div>} />
        <Route path="/batches" element={<div>Batches</div>} />
      </Routes>
    </>
  );
}

describe("RouteScrollReset", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback: FrameRequestCallback) => {
      callback(0);
      return 0;
    });
    Object.defineProperty(window, "scrollTo", {
      configurable: true,
      writable: true,
      value: vi.fn(),
    });
  });

  it("scrolls to the top when the pathname changes", () => {
    render(
      <MemoryRouter initialEntries={["/audit-history"]}>
        <TestRouter />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole("link", { name: "Manufacturers" }));

    expect(window.scrollTo).toHaveBeenCalledWith({ top: 0, left: 0, behavior: "auto" });
  });

  it("preserves hash anchor navigation", () => {
    render(
      <MemoryRouter initialEntries={["/audit-history"]}>
        <TestRouter />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole("link", { name: "Batches details" }));

    expect(window.scrollTo).not.toHaveBeenCalled();
  });
});
