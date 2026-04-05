import React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { ActionButton } from "@/components/ui/action-button";
import { createUiActionState } from "@/lib/ui-actions";

describe("ActionButton", () => {
  it("shows a visible reason when the action is disabled", () => {
    render(
      <ActionButton
        state={createUiActionState("disabled", "Choose a printer before you start this run.")}
        idleLabel="Start print run"
      />,
    );

    expect(screen.getByRole("button", { name: "Start print run" })).toBeDisabled();
    expect(screen.getByText("Choose a printer before you start this run.")).toBeInTheDocument();
  });

  it("switches to the pending label while work is in progress", () => {
    render(
      <ActionButton
        state={createUiActionState("pending", "Saving changes now.")}
        idleLabel="Save changes"
        pendingLabel="Saving..."
      />,
    );

    expect(screen.getByRole("button", { name: "Saving..." })).toBeDisabled();
    expect(screen.getByText("Saving changes now.")).toBeInTheDocument();
  });
});
