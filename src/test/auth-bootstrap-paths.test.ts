import { describe, expect, it } from "vitest";

import { shouldBootstrapCurrentUser } from "@/contexts/auth-bootstrap";

describe("auth bootstrap route policy", () => {
  it.each(["/login", "/accept-invite", "/forgot-password", "/reset-password", "/verify-email"])(
    "keeps %s available without protected session bootstrap",
    (path) => {
      expect(shouldBootstrapCurrentUser(path)).toBe(false);
    },
  );

  it.each(["/dashboard", "/batches", "/manufacturer/printer-agent/status"])(
    "requires protected session bootstrap for %s",
    (path) => {
      expect(shouldBootstrapCurrentUser(path)).toBe(true);
    },
  );
});
