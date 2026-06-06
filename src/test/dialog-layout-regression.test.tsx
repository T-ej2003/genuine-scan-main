import React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

describe("Dialog layout baseline", () => {
  it("keeps platform dialogs padded, viewport-safe, and footer-spaced by default", () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Invite manufacturer</DialogTitle>
            <DialogDescription>Add a manufacturer admin with a one-time activation link.</DialogDescription>
          </DialogHeader>
          <div>Dialog form body</div>
          <DialogFooter>
            <button type="button">Cancel</button>
            <button type="button">Save</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveClass("p-6");
    expect(dialog).toHaveClass("w-[calc(100vw-1rem)]");
    expect(dialog).toHaveClass("max-h-[calc(100vh-1rem)]");
    expect(dialog).toHaveClass("overflow-y-auto");
    expect(screen.getByText("Cancel").parentElement).toHaveClass("gap-3");
  });
});
