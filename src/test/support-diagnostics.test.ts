import { describe, expect, it } from "vitest";

import { formatSupportIssueSubmissionError } from "@/lib/support-diagnostics";

describe("formatSupportIssueSubmissionError", () => {
  it("turns nginx 413 html into a concise user-facing message", () => {
    const html = `<html><head><title>413 Request Entity Too Large</title></head><body><center><h1>413 Request Entity Too Large</h1></center></body></html>`;
    expect(formatSupportIssueSubmissionError(html)).toBe(
      "The attached screenshot was too large to upload. Please try again."
    );
  });

  it("strips markup and truncates noisy payloads", () => {
    const message = `<div><strong>Backend failed</strong><p>${"a".repeat(260)}</p></div>`;
    const formatted = formatSupportIssueSubmissionError(message);

    expect(formatted.startsWith("Backend failed aaaaa")).toBe(true);
    expect(formatted.endsWith("...")).toBe(true);
    expect(formatted.length).toBeLessThanOrEqual(220);
  });
});
