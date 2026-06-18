import { describe, expect, it } from "vitest";

import {
  buildManufacturerActivitySearchText,
  buildManufacturerPrintHistoryRow,
  getManufacturerActivityDisplay,
} from "@/lib/manufacturer-activity-display";

describe("manufacturer activity display", () => {
  it("translates local connector print events without leaking raw action names", () => {
    const display = getManufacturerActivityDisplay({
      action: "LOCAL_AGENT_PRINT_ITEM_ACKED",
      details: { printerName: "Zebra ZT410", batchName: "Spring Denim" },
    });

    expect(display.title).toBe("Print job received by printer connector");
    expect(display.description).toContain("printer connector accepted a label");
    expect(display.description).toContain("Zebra ZT410");
    expect(buildManufacturerActivitySearchText({ action: "LOCAL_AGENT_PRINT_ITEM_ACKED" }, display)).not.toContain(
      "local_agent_print_item_acked"
    );
  });

  it("uses a safe fallback for unknown internal events", () => {
    const display = getManufacturerActivityDisplay({
      action: "INTERNAL_RENDER_TOKEN_ROTATED",
      details: { renderUrl: "https://secret.example/render", token: "secret-token" },
    });

    expect(display.title).toBe("Workspace activity");
    expect(display.description).not.toContain("INTERNAL_RENDER_TOKEN_ROTATED");
    expect(display.description).not.toContain("secret-token");
    expect(display.description).not.toContain("https://secret.example");
  });

  it("builds user-facing print history rows from print job DTOs", () => {
    const row = buildManufacturerPrintHistoryRow({
      id: "550e8400-e29b-41d4-a716-446655440000",
      jobNumber: "PRINT-42",
      status: "CONFIRMED",
      quantity: 12,
      itemCount: 12,
      confirmedAt: "2026-06-08T12:00:00.000Z",
      batch: { name: "Spring Denim" },
      printer: { name: "Zebra ZT410" },
      session: { confirmedItems: 12, remainingToPrint: 0 },
      createdByUser: { name: "Factory Operator", email: "factory@example.com" },
    });

    expect(row.batchName).toBe("Spring Denim");
    expect(row.runLabel).toBe("PRINT-42");
    expect(row.requestedLabels).toBe(12);
    expect(row.printedLabels).toBe(12);
    expect(row.remainingLabels).toBe(0);
    expect(row.printerName).toBe("Zebra ZT410");
    expect(row.actorLabel).toContain("Factory Operator");
    expect(row.statusLabel).toBe("Confirmed");
  });

  it("uses a clear fallback when operator capture is unavailable", () => {
    const row = buildManufacturerPrintHistoryRow({
      id: "run-without-operator",
      status: "STOPPED",
      quantity: 10,
      itemCount: 10,
      batch: { name: "Spring Denim" },
      printer: { name: "Zebra ZT410" },
      session: { confirmedItems: 5, remainingToPrint: 5 },
    });

    expect(row.actorLabel).toBe("Operator not recorded");
    expect(row.statusLabel).toBe("Partially confirmed");
  });
});
