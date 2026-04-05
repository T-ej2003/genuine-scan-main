import { describe, expect, it } from "vitest";

import { UI_ACTION_INVENTORY } from "@/app/ui-action-inventory";
import { APP_PATHS } from "@/app/route-metadata";

describe("UI action inventory", () => {
  it("covers the core route set with unique route entries", () => {
    const routes = UI_ACTION_INVENTORY.map((item) => item.route);
    expect(new Set(routes).size).toBe(routes.length);

    for (const route of routes) {
      expect(Object.values(APP_PATHS)).toContain(route);
    }
  });

  it("tracks non-empty primary actions for every core route", () => {
    for (const item of UI_ACTION_INVENTORY) {
      expect(item.primaryActions.length).toBeGreaterThan(0);
      const ids = item.primaryActions.map((action) => action.id);
      expect(new Set(ids).size).toBe(ids.length);
      for (const action of item.primaryActions) {
        expect(action.id).toBeTruthy();
        expect(["working", "hidden_by_design", "disabled_with_reason", "needs_step_up"]).toContain(action.state);
        if (action.state !== "working") {
          expect(action.reason).toBeTruthy();
        }
      }
    }
  });
});
