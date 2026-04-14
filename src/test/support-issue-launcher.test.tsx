import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";

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
    toast: vi.fn(),
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
  formatSupportIssueSubmissionError: () => "Could not submit",
  getSupportNetworkLogs: () => [],
  getSupportRuntimeIssues: () => [],
  onSupportIssue: () => () => {},
  reportSupportRuntimeIssue: vi.fn(),
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
    expect(screen.getByText(/recent diagnostics automatically/i)).toBeInTheDocument();
  });
});
