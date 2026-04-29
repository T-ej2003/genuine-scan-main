import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import type { User, UserRole } from "@/types";

const mockLogout = vi.fn();

const authState = vi.hoisted(() => ({
  user: null as User | null,
}));

window.HTMLElement.prototype.scrollIntoView = vi.fn();

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: authState.user,
    logout: mockLogout,
  }),
}));

vi.mock("next-themes", () => ({
  useTheme: () => ({
    resolvedTheme: "light",
    setTheme: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

vi.mock("@/help/contextual-help", () => ({
  getContextualHelpRoute: () => "/help/support",
}));

vi.mock("@/components/support/SupportIssueLauncher", () => ({
  SupportIssueLauncher: () => <button type="button">Report issue</button>,
}));

vi.mock("@/features/layout/hooks", () => ({
  useDashboardNotificationCenter: () => ({
    unreadNotifications: 0,
    visibleNotifications: [],
    notificationsLoading: false,
    notificationsLive: false,
    clearingNotificationIdSet: new Set<string>(),
    clearingNotifications: false,
    hasVisibleNotifications: false,
    notificationPanelCleared: false,
    canClearNotifications: false,
    markAllNotificationsRead: vi.fn(),
    markNotificationRead: vi.fn(),
    clearNotifications: vi.fn(),
  }),
  useOperationalAttentionQueue: () => ({
    data: null,
    isLoading: false,
    isFetching: false,
  }),
}));

vi.mock("@/features/layout/useManufacturerPrinterConnection", () => ({
  useManufacturerPrinterConnection: () => ({
    isManufacturer: authState.user?.role === "manufacturer",
    printerModeLabel: "Ready",
    printerTitle: "Printing ready",
    effectivePrinterReady: true,
    printerDegraded: false,
    openPrinterConnectionDialog: vi.fn(),
    clearPrinterDialogSession: vi.fn(),
    printerToneClass: "",
    goToConnectorDownload: vi.fn(),
    managedNetworkPrinters: [{ id: "printer-1" }],
    printerOnboardingOpen: false,
    setPrinterOnboardingOpen: vi.fn(),
    localPrinterAgent: null,
    printerHasInventory: true,
    selectedPrinterName: "Factory printer",
    goToHelp: vi.fn(),
    dismissPrinterOnboarding: vi.fn(),
    printerDialogOpen: false,
    setPrinterDialogOpen: vi.fn(),
    effectivePrinterDiagnostics: { tone: "success", summary: "Ready", detail: "Ready", badgeLabel: "Ready", nextSteps: [] },
    printerUnavailable: false,
    printerIdentity: null,
    printerSummaryMessage: "Ready",
    printerNextStep: "Ready",
    printerUpdatedLabel: "Updated just now",
    printerFeedLabel: "Refreshes automatically",
    printerStatusLive: false,
    printerDegradedMessage: "",
    selectedPrinter: null,
    shouldUseManagedPrinterSummary: false,
    preferredManagedNetworkPrinter: null,
    printerName: "Factory printer",
    printerAgeSeconds: 0,
    detectedPrinters: [],
    activePrinterId: "printer-1",
    selectedLocalPrinterId: "printer-1",
    selectedPrinterIsActive: true,
    printerDiscoveryCountLabel: "1 printer",
    printerSwitching: false,
    setSelectedLocalPrinterId: vi.fn(),
    refreshPrinterConnectionStatus: vi.fn(),
    goToPrinterSetup: vi.fn(),
    goToBatches: vi.fn(),
    switchLocalPrinter: vi.fn(),
    workstationDeviceName: "Factory Mac",
  }),
}));

vi.mock("@/features/layout/components/PrinterDialogs", () => ({
  PrinterOnboardingDialog: () => null,
  PrinterStatusDialog: () => null,
}));

const buildUser = (role: UserRole): User => ({
  id: `${role}-1`,
  email: `${role}@example.com`,
  name:
    role === "super_admin"
      ? "Platform User"
      : role === "licensee_admin"
        ? "Brand User"
        : "Factory User",
  role,
  rawRole: role.toUpperCase(),
  emailVerifiedAt: null,
  pendingEmail: null,
  pendingEmailRequestedAt: null,
  licenseeId: role === "super_admin" ? undefined : "lic-1",
  orgId: null,
  licensee: role === "super_admin" ? null : { id: "lic-1", name: "Acme Denim", brandName: "Acme Denim", prefix: "ACM" },
  linkedLicensees: undefined,
  createdAt: "2026-04-29T00:00:00.000Z",
  isActive: true,
  deletedAt: null,
  auth: null,
});

const renderShellForRole = (role: UserRole) => {
  authState.user = buildUser(role);
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <DashboardLayout>
        <div>Workspace content</div>
      </DashboardLayout>
    </MemoryRouter>
  );
};

const getSidebarNav = () => screen.getByRole("navigation", { name: /authenticated mscqr navigation/i });

const expectNavLabels = (labels: string[]) => {
  const nav = within(getSidebarNav());
  for (const label of labels) {
    expect(nav.getByRole("link", { name: new RegExp(label, "i") })).toBeInTheDocument();
  }
};

const expectNavLabelsAbsent = (labels: string[]) => {
  const nav = within(getSidebarNav());
  for (const label of labels) {
    expect(nav.queryByRole("link", { name: new RegExp(label, "i") })).not.toBeInTheDocument();
  }
};

describe("Dashboard shell nav visibility", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authState.user = null;
  });

  it("shows Platform Admin navigation without exposing raw technical labels", () => {
    renderShellForRole("super_admin");

    expect(screen.getAllByText("Platform Admin").length).toBeGreaterThan(0);
    expectNavLabels(["Overview", "QR Requests", "Batches", "Scans", "Brands", "Manufacturers", "Issues", "History", "Settings"]);
    expect(screen.getByText("Advanced")).toBeInTheDocument();

    expect(screen.queryByText("Licensee Admin")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /printer diagnostics/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /raw evidence/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /technical logs/i })).not.toBeInTheDocument();
  });

  it("shows only authorized Brand Admin shell navigation", () => {
    renderShellForRole("licensee_admin");

    expect(screen.getAllByText("Brand Admin").length).toBeGreaterThan(0);
    expect(screen.queryByText("Licensee Admin")).not.toBeInTheDocument();
    expectNavLabels(["Overview", "QR Requests", "Batches", "Scans", "Manufacturers", "History", "Settings"]);
    expectNavLabelsAbsent(["Brands", "Issues", "Printing", "Governance", "Release Readiness", "Printer Diagnostics", "Raw Evidence", "Technical Logs"]);
    expect(screen.queryByText("Advanced")).not.toBeInTheDocument();
  });

  it("shows only authorized Manufacturer Admin shell navigation", () => {
    renderShellForRole("manufacturer");

    expect(screen.getAllByText("Manufacturer Admin").length).toBeGreaterThan(0);
    expect(screen.queryByText("Licensee Admin")).not.toBeInTheDocument();
    expectNavLabels(["Overview", "Batches", "Printing", "Scans", "History", "Settings"]);
    expectNavLabelsAbsent(["QR Requests", "Brands", "Manufacturers", "Issues", "Governance", "Release Readiness", "Printer Diagnostics", "Raw Evidence", "Technical Logs"]);
    expect(screen.queryByText("Advanced")).not.toBeInTheDocument();
  });

  it.each(["licensee_admin", "manufacturer"] as UserRole[])(
    "keeps unauthorized routes out of workspace search for %s",
    (role) => {
      renderShellForRole(role);

      fireEvent.click(screen.getAllByRole("button", { name: /open command palette/i })[0]);

      expect(screen.getAllByText("Workspace search").length).toBeGreaterThan(0);
      expect(screen.getByRole("option", { name: /overview/i })).toBeInTheDocument();
      expect(screen.queryByRole("option", { name: /brands/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("option", { name: /issues/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("option", { name: /governance/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("option", { name: /release readiness/i })).not.toBeInTheDocument();
    }
  );
});
