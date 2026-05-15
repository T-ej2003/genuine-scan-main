import { describe, expect, it } from "vitest";

import { classifyApiError, friendlyEmailDeliveryMessage, getInviteDeliveryState } from "@/lib/api/friendly-errors";

describe("friendly API errors", () => {
  it("maps duplicate create conflicts to admin-safe copy", () => {
    const mapped = classifyApiError({
      success: false,
      status: 409,
      code: "DUPLICATE_LICENSEE_OR_ADMIN",
      error: "Unique constraint failed",
    });

    expect(mapped.kind).toBe("conflict");
    expect(mapped.title).toBe("Already exists");
    expect(mapped.description).toContain("A brand/admin with these details already exists");
  });

  it("maps step-up and timeout outcomes without destructive create failure copy", () => {
    expect(classifyApiError({ success: false, status: 428, code: "STEP_UP_REQUIRED" }).kind).toBe("step_up_required");

    const timeout = classifyApiError({ success: false, code: "REQUEST_TIMEOUT", unknownOutcome: true });
    expect(timeout.kind).toBe("timeout_unknown");
    expect(timeout.unknownOutcome).toBe(true);
    expect(timeout.title).not.toMatch(/failed/i);
  });

  it("normalizes invite delivery fields from old and new response shapes", () => {
    expect(
      getInviteDeliveryState({
        invite: {
          created: true,
          emailSent: false,
          emailErrorCode: "SMTP_CONFIG_MISSING",
          inviteLink: "https://example.test/invite",
        },
      })
    ).toEqual({
      created: true,
      emailSent: false,
      emailErrorCode: "SMTP_CONFIG_MISSING",
      inviteLink: "https://example.test/invite",
    });

    expect(friendlyEmailDeliveryMessage("SMTP_AUTH_FAILED")).toContain("mail provider rejected");
  });
});
