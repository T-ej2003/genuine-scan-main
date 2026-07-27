import React from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";

import { isSafeInternalRoute } from "@/features/layout/navigation-safety";

describe("React Router 7 security compatibility", () => {
  it("preserves nested routes and deep links", () => {
    render(
      <MemoryRouter initialEntries={["/verify/MSCQR_CODE?source=label"]}>
        <Routes>
          <Route path="/verify/:code" element={<div>verified route</div>} />
          <Route path="*" element={<div>not found</div>} />
        </Routes>
      </MemoryRouter>
    );
    expect(screen.getByText("verified route")).toBeInTheDocument();
  });

  it.each([
    ["https://evil.example/dashboard"],
    ["//evil.example/dashboard"],
    ["/\\evil.example/dashboard"],
    ["javascript:alert(1)"],
    ["/dashboard\\@evil.example"],
  ])("rejects unsafe dynamic navigation %s", (route) => {
    expect(isSafeInternalRoute(route)).toBe(false);
  });

  it("accepts a reviewed internal route with bounded query state", () => {
    expect(isSafeInternalRoute("/batches?batchId=123")).toBe(true);
  });
});
