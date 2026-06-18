import { describe, expect, it } from "vitest";

import { resolveNotificationTarget } from "@/features/layout/navigation-safety";

describe("notification deep-link routing", () => {
  it("routes reissue notifications to the batch reissue section with highlight metadata", () => {
    expect(
      resolveNotificationTarget({
        id: "notification-1",
        data: {
          entityType: "reissue_request",
          batchId: "batch-1",
          reissueRequestId: "reissue-1",
          replacementPrintJobId: "job-2",
        },
      } as any)
    ).toBe("/batches?batchId=batch-1&tab=reissue&reissueRequestId=reissue-1&printJobId=job-2");
  });

  it("routes print-run notifications to operations and rejects unsafe target URLs", () => {
    expect(
      resolveNotificationTarget({
        id: "notification-2",
        data: {
          targetRoute: "https://example.test/steal",
          entityType: "print_run",
          batchId: "batch-2",
          printJobId: "job-3",
        },
      } as any)
    ).toBe("/batches?batchId=batch-2&tab=operations&printJobId=job-3");
  });
});
