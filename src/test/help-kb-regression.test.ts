import { describe, expect, it } from "vitest";

import { HELP_KB } from "@/help/kb";

describe("help KB auth guidance", () => {
  it("describes admin MFA as available instead of disabled", () => {
    const entry = HELP_KB.find((item) => item.id === "mfa-temporarily-disabled");

    expect(entry).toBeDefined();
    expect(entry?.answer).toContain("Admin MFA is available in MSCQR");
    expect(entry?.answer).not.toContain("temporarily disabled");
  });
});
