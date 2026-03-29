import { APP_PATHS } from "@/app/route-metadata";

export type UiRouteActionState =
  | "working"
  | "hidden_by_design"
  | "disabled_with_reason"
  | "needs_step_up";

export type UiRouteActionInventoryItem = {
  id: string;
  state: UiRouteActionState;
  reason?: string;
};

export const UI_ACTION_INVENTORY = [
  {
    route: APP_PATHS.dashboard,
    primaryActions: [
      { id: "open-notifications", state: "working" },
      { id: "open-help", state: "working" },
    ],
  },
  {
    route: APP_PATHS.batches,
    primaryActions: [
      { id: "refresh-batches", state: "working" },
      { id: "batch-workspace-open", state: "working" },
      { id: "manufacturer-create-print-job", state: "working" },
    ],
  },
  {
    route: APP_PATHS.printerSetup,
    primaryActions: [
      { id: "save-printer-setup", state: "working" },
      {
        id: "run-test-print",
        state: "hidden_by_design",
        reason: "Shown after at least one saved printer is available to test.",
      },
    ],
  },
  {
    route: APP_PATHS.connectorDownload,
    primaryActions: [
      { id: "download-printer-helper-mac", state: "working" },
      { id: "download-printer-helper-windows", state: "working" },
      { id: "open-printer-helper-guide", state: "working" },
    ],
  },
  {
    route: APP_PATHS.verify,
    primaryActions: [
      { id: "verify-open-incident-drawer", state: "working" },
      { id: "verify-report-submit", state: "working" },
      { id: "verify-track-ticket", state: "working" },
    ],
  },
  {
    route: APP_PATHS.support,
    primaryActions: [
      { id: "support-apply-filters", state: "working" },
      { id: "support-ticket-save", state: "working" },
      { id: "support-ticket-message-submit", state: "working" },
      { id: "support-issue-report-reply", state: "working" },
    ],
  },
  {
    route: APP_PATHS.incidentResponse,
    primaryActions: [
      { id: "incident-apply-filters", state: "working" },
      { id: "incident-save-updates", state: "working" },
      { id: "incident-send-customer-update", state: "working" },
      { id: "incident-upload-evidence", state: "working" },
    ],
  },
  {
    route: APP_PATHS.account,
    primaryActions: [
      { id: "account-save-profile", state: "working" },
      {
        id: "account-change-password",
        state: "needs_step_up",
        reason: "Password changes may ask the user to confirm their identity again.",
      },
      { id: "account-revoke-session", state: "working" },
    ],
  },
] as const;
