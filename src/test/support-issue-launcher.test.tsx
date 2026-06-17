import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";
import apiClient from "@/lib/api-client";

const supportIssueMocks = vi.hoisted(() => ({
  toast: vi.fn(),
  formatSupportIssueSubmissionError: vi.fn(() => "Could not submit"),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "licensee-1",
      role: "licensee_admin",
      name: "Launch User",
      email: "launch@example.com",
    },
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: supportIssueMocks.toast,
  }),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    createSupportIssueReport: vi.fn(),
  },
}));

vi.mock("@/lib/support-diagnostics", () => ({
  buildSupportDiagnosticsPayload: () => ({}),
  captureSupportScreenshot: vi.fn().mockResolvedValue(null),
  formatSupportIssueSubmissionError: supportIssueMocks.formatSupportIssueSubmissionError,
  getSanitizedSupportPageUrl: () => "https://app.example.test/history?page=2",
  getSanitizedSupportSourcePath: () => "/history?page=2",
  getSupportNetworkLogs: () => [],
  getSupportRuntimeIssues: () => [],
  onSupportIssue: () => () => {},
  reportSupportRuntimeIssue: vi.fn(),
  serializeSupportDiagnosticsPayload: () => "{}",
  SUPPORT_SCREENSHOT_MAX_BYTES: 550 * 1024,
}));

describe("SupportIssueLauncher", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows the privacy notice when the dialog opens", async () => {
    render(<SupportIssueLauncher />);

    fireEvent.click(screen.getByRole("button", { name: /report issue/i }));

    expect(await screen.findByText(/privacy notice for support evidence/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /privacy notice/i })).toHaveAttribute("href", "/privacy");
    expect(screen.getByText(/recent redacted diagnostics automatically/i)).toBeInTheDocument();
  });

  it("shows a friendly edge-block error without raw infrastructure text", async () => {
    vi.mocked(apiClient.createSupportIssueReport).mockResolvedValueOnce({
      success: false,
      status: 403,
      code: "FORBIDDEN",
      error: "ERROR: The request could not be satisfied. Request blocked.",
    });
    supportIssueMocks.formatSupportIssueSubmissionError.mockReturnValueOnce(
      "We could not submit the report right now. Please try again or contact support."
    );

    render(<SupportIssueLauncher />);

    fireEvent.click(screen.getByRole("button", { name: /report issue/i }));
    fireEvent.change(screen.getByPlaceholderText(/batch history did not update/i), {
      target: { value: "Unable to submit support report" },
    });
    fireEvent.change(screen.getByPlaceholderText(/describe what you were trying to do/i), {
      target: { value: "The support form failed in production." },
    });
    fireEvent.click(screen.getByRole("button", { name: /send report/i }));

    await waitFor(() => {
      expect(supportIssueMocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Could not submit report",
          description: "We could not submit the report right now. Please try again or contact support.",
          variant: "destructive",
        })
      );
    });
    expect(supportIssueMocks.formatSupportIssueSubmissionError).toHaveBeenCalledWith(
      "ERROR: The request could not be satisfied. Request blocked.",
      { status: 403, code: "FORBIDDEN", unknownOutcome: undefined }
    );
  });
});
