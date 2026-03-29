export type UiActionAvailability = "enabled" | "disabled" | "hidden" | "step_up" | "pending";

export type UiActionState = {
  availability: UiActionAvailability;
  reason?: string | null;
};

export const isUiActionVisible = (state: UiActionState | UiActionAvailability | null | undefined) => {
  const availability = typeof state === "string" ? state : state?.availability;
  return availability !== "hidden";
};

export const isUiActionDisabled = (state: UiActionState | UiActionAvailability | null | undefined) => {
  const availability = typeof state === "string" ? state : state?.availability;
  return availability === "disabled" || availability === "step_up" || availability === "pending";
};

export const getUiActionReason = (state: UiActionState | null | undefined) =>
  String(state?.reason || "").trim();

export const createUiActionState = (
  availability: UiActionAvailability,
  reason?: string | null,
): UiActionState => ({
  availability,
  reason: String(reason || "").trim() || null,
});
