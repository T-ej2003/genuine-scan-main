import React, { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PrinterOnboardingDialog } from "@/features/layout/components/PrinterDialogs";

describe("printer onboarding dialog", () => {
  it("closes and releases focus before navigating to the installer", () => {
    const events: string[] = [];
    const Preview = () => {
      const [open, setOpen] = useState(true);
      return <PrinterOnboardingDialog
        open={open}
        onOpenChange={(next) => { events.push(`open:${next}`); setOpen(next); }}
        localPrinterAgent={{ reachable: false } as any}
        printerHasInventory={false}
        onInstallConnector={() => events.push("install")}
        onCheckAgain={() => undefined}
        onOpenHelp={() => undefined}
        onCloseForNow={() => setOpen(false)}
      />;
    };

    render(<Preview />);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Install printer helper" }));
    expect(events).toEqual(["open:false", "install"]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
