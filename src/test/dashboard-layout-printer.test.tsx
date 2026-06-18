import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import {
  clearActivePrintSession,
  getActivePrintSessionSnapshot,
  updateActivePrintSession,
} from "@/lib/active-print-session";
import { CONSENT_STORAGE_KEY, type ConsentState } from "@/lib/consent";
import { renderWithQueryClient } from "@/test/render-with-query-client";

const localStorageState = new Map<string, string>();
const sessionStorageState = new Map<string, string>();

const functionalConsent: ConsentState = {
  version: 1,
  updatedAt: "2026-05-04T00:00:00.000Z",
  categories: {
    functional: true,
    analytics: false,
    marketing: false,
  },
};

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "manufacturer-1", role: "manufacturer", name: "Factory User", email: "factory@example.com" },
    logout: vi.fn(),
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
  SupportIssueLauncher: () => <div data-testid="support-launcher" />,
}));

vi.mock("@/lib/support-diagnostics", () => ({
  buildSupportDiagnosticsPayload: () => ({}),
  captureSupportScreenshot: vi.fn().mockResolvedValue(null),
}));

vi.mock("@/lib/anon-device", () => ({
  getOrCreateAnonDeviceId: () => "device-1",
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    configureLocalPrintAgentBackend: vi.fn(),
    getNotifications: vi.fn(),
    getOperationalAttentionQueue: vi.fn(),
    streamNotifications: vi.fn(),
    listRegisteredPrinters: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    reportPrinterHeartbeat: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    streamPrinterConnectionStatus: vi.fn(),
  },
}));

describe("DashboardLayout printer connection dialog", () => {
  const onboardingKey = "manufacturer-printer-onboarding:v1:manufacturer-1:device-1";
  let emitPrinterConnectionStatus: ((payload: any) => void) | null = null;

  const trustedPrinterStatus: any = {
    connected: true,
    trusted: true,
    compatibilityMode: false,
    compatibilityReason: null,
    eligibleForPrinting: true,
    connectionClass: "TRUSTED",
    stale: false,
    requiredForPrinting: true,
    trustStatus: "TRUSTED",
    trustReason: "Trusted printer ready",
    lastHeartbeatAt: "2026-03-13T19:23:36.000Z",
    ageSeconds: 0,
    registrationId: "printer-managed-1",
    agentId: "agent-1",
    deviceFingerprint: "device-fingerprint",
    mtlsFingerprint: "mtls-fingerprint",
    printerName: "Canon TS4100i series 2",
    printerId: "printer-1",
    selectedPrinterId: "printer-1",
    selectedPrinterName: "Canon TS4100i series 2",
    deviceName: "Factory Mac",
    agentVersion: "2026.3.13",
    capabilitySummary: null,
    printers: [
      {
        printerId: "printer-1",
        printerName: "Canon TS4100i series 2",
        model: "TS4100i",
        connection: "ipps",
        online: true,
        isDefault: true,
        protocols: ["ipp"],
        languages: ["pdf"],
        mediaSizes: ["A4"],
        dpi: 300,
      },
    ],
    calibrationProfile: null,
    error: null,
  };

  const emitPrinterStatus = (status: any) => {
    emitPrinterConnectionStatus?.({
      type: "printer.status.updated",
      serverTime: status.lastHeartbeatAt,
      status,
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
    clearActivePrintSession();
    emitPrinterConnectionStatus = null;
    localStorageState.clear();
    sessionStorageState.clear();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => localStorageState.get(key) ?? null,
        setItem: (key: string, value: string) => {
          localStorageState.set(key, String(value));
        },
        removeItem: (key: string) => {
          localStorageState.delete(key);
        },
        clear: () => {
          localStorageState.clear();
        },
      },
    });
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => sessionStorageState.get(key) ?? null,
        setItem: (key: string, value: string) => {
          sessionStorageState.set(key, String(value));
        },
        removeItem: (key: string) => {
          sessionStorageState.delete(key);
        },
        clear: () => {
          sessionStorageState.clear();
        },
      },
    });
    localStorageState.set(CONSENT_STORAGE_KEY, JSON.stringify(functionalConsent));

    vi.mocked(apiClient.getNotifications).mockResolvedValue({
      success: true,
      data: { notifications: [], unread: 0 },
    } as Awaited<ReturnType<typeof apiClient.getNotifications>>);
    vi.mocked(apiClient.getOperationalAttentionQueue).mockResolvedValue({
      success: true,
      data: {
        generatedAt: "2026-05-16T00:00:00.000Z",
        summary: {
          unreadNotifications: 0,
          reviewSignals: 0,
          printOperations: 0,
          supportEscalations: 0,
          auditEvents24h: 0,
        },
        items: [],
      },
    } as Awaited<ReturnType<typeof apiClient.getOperationalAttentionQueue>>);
    vi.mocked(apiClient.configureLocalPrintAgentBackend).mockResolvedValue({
      success: true,
    } as Awaited<ReturnType<typeof apiClient.configureLocalPrintAgentBackend>>);
    vi.mocked(apiClient.streamNotifications).mockImplementation(() => () => undefined);
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onMessage) => {
      emitPrinterConnectionStatus = onMessage as (payload: any) => void;
      return () => {
        emitPrinterConnectionStatus = null;
      };
    });
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({
      success: true,
      data: [],
    } as Awaited<ReturnType<typeof apiClient.listRegisteredPrinters>>);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: false,
      error: "Local print agent is unavailable",
    } as Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>);
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: true } as Awaited<ReturnType<typeof apiClient.reportPrinterHeartbeat>>);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        requiredForPrinting: true,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        registrationId: null,
        agentId: null,
        deviceFingerprint: null,
        mtlsFingerprint: null,
        printerName: null,
        printerId: null,
        selectedPrinterId: null,
        selectedPrinterName: null,
        deviceName: null,
        agentVersion: null,
        capabilitySummary: null,
        printers: [],
        calibrationProfile: null,
        error: "Local print agent is unavailable",
      },
    } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);
  });

  it("opens the printer dialog even when the local agent is unreachable", async () => {
    localStorageState.set(onboardingKey, "dismissed");

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole("button", { name: /printing needs review/i }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });

    expect(
      screen.getByText(/check whether printing is ready, switch printers on this computer when needed/i)
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Refresh status" }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /open printer setup/i })).toBeInTheDocument();
  });

  it("shows first-run printer onboarding for manufacturers", async () => {
    renderWithQueryClient(
      <MemoryRouter initialEntries={["/batches"]}>
        <DashboardLayout>
          <div>Batches content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Set up printing on this computer")).toBeInTheDocument();
    });
    expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).not.toHaveBeenCalled();
    expect(screen.getByText(/The browser cannot install printers, drivers, or desktop apps by itself/i)).toBeInTheDocument();
    expect(screen.getByText(/If the computer can see the printer, MSCQR will pick it up automatically/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /install printer helper/i })).toBeInTheDocument();
    expect(screen.getByText(/download the Mac or Windows installer for this computer/i)).toBeInTheDocument();
  });

  it("does not auto-open printer onboarding away from Batches", async () => {
    renderWithQueryClient(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    expect(screen.queryByText("Set up printing on this computer")).not.toBeInTheDocument();
    expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).not.toHaveBeenCalled();
  });

  it("keeps saved network printers visible instead of pushing helper install when a saved route is ready", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({
      success: true,
      data: [
        {
          id: "printer-managed-1",
          name: "Factory LAN Printer",
          connectionType: "NETWORK_DIRECT",
          commandLanguage: "ZPL",
          isActive: true,
          isDefault: true,
          registryStatus: {
            state: "READY",
            summary: "Ready",
            detail: "Raw TCP validation succeeded.",
          },
        },
      ],
    } as Awaited<ReturnType<typeof apiClient.listRegisteredPrinters>>);

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    expect(screen.queryByText("Set up printing on this computer")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /printing needs review/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /printer setup/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /install printer helper/i })).not.toBeInTheDocument();
  });

  it("does not auto-open the helper when the printer is ready", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: true,
        connectionClass: "TRUSTED",
        stale: false,
        requiredForPrinting: true,
        trustStatus: "TRUSTED",
        trustReason: "Trusted printer ready",
        lastHeartbeatAt: "2026-03-13T19:23:36.000Z",
        ageSeconds: 0,
        registrationId: "printer-managed-1",
        agentId: "agent-1",
        deviceFingerprint: "device-fingerprint",
        mtlsFingerprint: "mtls-fingerprint",
        printerName: "Canon TS4100i series 2",
        printerId: "printer-1",
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Canon TS4100i series 2",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.13",
        capabilitySummary: null,
        printers: [
          {
            printerId: "printer-1",
            printerName: "Canon TS4100i series 2",
            model: "TS4100i",
            connection: "ipps",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["pdf"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
        ],
        calibrationProfile: null,
        error: null,
      },
    } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    emitPrinterStatus(trustedPrinterStatus);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /printing ready/i })).toBeInTheDocument();
    });

    expect(screen.queryByText("Printing Status")).not.toBeInTheDocument();
  });

  it("shows secure verification pending as a blocking helper refresh notice", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        printerName: "Canon TS4100i series 2",
        printerId: "printer-1",
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Canon TS4100i series 2",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.28",
        printers: [
          {
            printerId: "printer-1",
            printerName: "Canon TS4100i series 2",
            model: "TS4100i",
            connection: "ipps",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["pdf"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
        ],
      },
    } as Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>);
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({
      success: true,
      degraded: true,
      data: {
        connected: true,
        trusted: false,
        compatibilityMode: true,
        degraded: true,
        compatibilityReason: "Heartbeat accepted in degraded mode while secure printer storage is recovering.",
        eligibleForPrinting: true,
        connectionClass: "COMPATIBILITY",
        stale: false,
        requiredForPrinting: true,
        trustStatus: "DEGRADED",
        trustReason: "Printer heartbeat storage is temporarily unavailable",
        lastHeartbeatAt: "2026-03-28T10:00:00.000Z",
        ageSeconds: 0,
        registrationId: null,
        agentId: "agent-1",
        deviceFingerprint: "device-fingerprint",
        mtlsFingerprint: null,
        printerName: "Canon TS4100i series 2",
        printerId: "printer-1",
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Canon TS4100i series 2",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.28",
        capabilitySummary: null,
        printers: [
          {
            printerId: "printer-1",
            printerName: "Canon TS4100i series 2",
            model: "TS4100i",
            connection: "ipps",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["pdf"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
        ],
        calibrationProfile: null,
        error: null,
      },
    } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    emitPrinterStatus({
      ...trustedPrinterStatus,
      trusted: false,
      compatibilityMode: true,
      compatibilityReason: "Heartbeat accepted in degraded mode while secure printer storage is recovering.",
      connectionClass: "COMPATIBILITY",
      trustStatus: "DEGRADED",
      trustReason: "Printer heartbeat storage is temporarily unavailable",
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /printing needs review/i })).toBeInTheDocument();
    });
    expect(vi.mocked(apiClient.getPrinterConnectionStatus)).not.toHaveBeenCalled();
    expect(screen.queryByText("Recovery mode")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /printing needs review/i }));

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });

    expect(screen.getAllByText(/Printer verification expired\. Refresh printer helper before printing\./i).length).toBeGreaterThan(0);
    expect(screen.queryByText("Recovery mode")).not.toBeInTheDocument();
  });

  it("preserves last-known ready state and keeps helper closed when status refresh is rate-limited", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        printerName: "ZDesigner ZT410-300dpi ZPL",
        printerId: "zdesigner-zt410",
        selectedPrinterId: "zdesigner-zt410",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.28",
        printers: [
          {
            printerId: "zdesigner-zt410",
            printerName: "ZDesigner ZT410-300dpi ZPL",
            model: "ZT410",
            connection: "usb",
            online: true,
            isDefault: true,
            protocols: ["raw-9100"],
            languages: ["ZPL"],
            mediaSizes: ["Label"],
            dpi: 300,
          },
        ],
      },
    } as Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>);
    vi.mocked(apiClient.getPrinterConnectionStatus)
      .mockResolvedValueOnce({
        success: true,
        data: {
          connected: true,
          trusted: true,
          compatibilityMode: false,
          compatibilityReason: null,
          eligibleForPrinting: true,
          connectionClass: "TRUSTED",
          stale: false,
          requiredForPrinting: true,
          trustStatus: "TRUSTED",
          trustReason: "Trusted printer ready",
          lastHeartbeatAt: "2026-03-13T19:23:36.000Z",
          ageSeconds: 0,
          registrationId: "printer-managed-1",
          agentId: "agent-1",
          deviceFingerprint: "device-fingerprint",
          mtlsFingerprint: "mtls-fingerprint",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          printerId: "zdesigner-zt410",
          selectedPrinterId: "zdesigner-zt410",
          selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
          deviceName: "Factory Mac",
          agentVersion: "2026.3.13",
          capabilitySummary: null,
          printers: [
            {
              printerId: "zdesigner-zt410",
              printerName: "ZDesigner ZT410-300dpi ZPL",
              model: "ZT410",
              connection: "usb",
              online: true,
              isDefault: true,
              protocols: ["raw-9100"],
              languages: ["ZPL"],
              mediaSizes: ["Label"],
              dpi: 300,
            },
          ],
          calibrationProfile: null,
          error: null,
        },
      } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>)
      .mockResolvedValue({
        success: false,
        status: 429,
        code: "RATE_LIMITED",
        retryAfterSec: 60,
        error: "Too many printer status requests. Please wait before retrying.",
      } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    emitPrinterStatus({
      ...trustedPrinterStatus,
      printerName: "ZDesigner ZT410-300dpi ZPL",
      printerId: "zdesigner-zt410",
      selectedPrinterId: "zdesigner-zt410",
      selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printers: [
        {
          printerId: "zdesigner-zt410",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "ZT410",
          connection: "usb",
          online: true,
          isDefault: true,
          protocols: ["raw-9100"],
          languages: ["ZPL"],
          mediaSizes: ["Label"],
          dpi: 300,
        },
      ],
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /printing ready/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /printing ready/i }));
    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });
    fireEvent.click(screen.getAllByRole("button", { name: /refresh status/i })[0]);

    await waitFor(() => {
      expect(screen.getAllByText(/printer status refresh is temporarily paused\. printing can continue/i).length).toBeGreaterThan(0);
    });
    expect(screen.queryByText("Recovery mode")).not.toBeInTheDocument();
  });

  it("keeps ZDesigner selected instead of switching to Canon AirPrint", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        printerName: "ZDesigner ZT410-300dpi ZPL",
        printerId: "zdesigner-zt410",
        selectedPrinterId: "zdesigner-zt410",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.28",
        printers: [
          {
            printerId: "canon-airprint",
            printerName: "Canon TS4100i series-AirPrint",
            model: "TS4100i",
            connection: "AirPrint",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["PDF"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
          {
            printerId: "zdesigner-zt410",
            printerName: "ZDesigner ZT410-300dpi ZPL",
            model: "ZT410",
            connection: "USB",
            online: true,
            isDefault: false,
            protocols: ["raw-9100"],
            languages: ["ZPL"],
            mediaSizes: ["Label"],
            dpi: 300,
          },
        ],
      },
    } as Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: true,
        connectionClass: "TRUSTED",
        stale: false,
        requiredForPrinting: true,
        trustStatus: "TRUSTED",
        trustReason: "Trusted printer ready",
        lastHeartbeatAt: "2026-03-13T19:23:36.000Z",
        ageSeconds: 0,
        registrationId: "printer-managed-1",
        agentId: "agent-1",
        deviceFingerprint: "device-fingerprint",
        mtlsFingerprint: "mtls-fingerprint",
        printerName: "ZDesigner ZT410-300dpi ZPL",
        printerId: "zdesigner-zt410",
        selectedPrinterId: "zdesigner-zt410",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.13",
        capabilitySummary: null,
        printers: [
          {
            printerId: "canon-airprint",
            printerName: "Canon TS4100i series-AirPrint",
            model: "TS4100i",
            connection: "AirPrint",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["PDF"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
          {
            printerId: "zdesigner-zt410",
            printerName: "ZDesigner ZT410-300dpi ZPL",
            model: "ZT410",
            connection: "USB",
            online: true,
            isDefault: false,
            protocols: ["raw-9100"],
            languages: ["ZPL"],
            mediaSizes: ["Label"],
            dpi: 300,
          },
        ],
        calibrationProfile: null,
        error: null,
      },
    } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    emitPrinterStatus({
      ...trustedPrinterStatus,
      printerName: "ZDesigner ZT410-300dpi ZPL",
      printerId: "zdesigner-zt410",
      selectedPrinterId: "zdesigner-zt410",
      selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printers: [
        {
          printerId: "canon-airprint",
          printerName: "Canon TS4100i series-AirPrint",
          model: "TS4100i",
          connection: "AirPrint",
          online: true,
          isDefault: true,
          protocols: ["ipp"],
          languages: ["PDF"],
          mediaSizes: ["A4"],
          dpi: 300,
        },
        {
          printerId: "zdesigner-zt410",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "ZT410",
          connection: "USB",
          online: true,
          isDefault: false,
          protocols: ["raw-9100"],
          languages: ["ZPL"],
          mediaSizes: ["Label"],
          dpi: 300,
        },
      ],
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /printing ready/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole("button", { name: /printing ready/i }));

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });
    expect(screen.getAllByText("ZDesigner ZT410-300dpi ZPL").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /active printer/i })).toBeInTheDocument();
  });

  it("turns the header printing status into active print progress recovery", async () => {
    localStorageState.set(onboardingKey, "dismissed");
    updateActivePrintSession({
      active: true,
      jobId: "job-live",
      modalOpen: false,
      terminal: false,
    });

    renderWithQueryClient(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    const recoveryButton = await screen.findByRole("button", { name: /resume print progress/i });
    fireEvent.click(recoveryButton);

    expect(getActivePrintSessionSnapshot().recoveryRequestId).toBe(1);
    expect(apiClient.getPrinterConnectionStatus).not.toHaveBeenCalled();
  });

  it("keeps the normal printer status behavior when no active print job exists", async () => {
    localStorageState.set(onboardingKey, "dismissed");

    renderWithQueryClient(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    const statusButton = await screen.findByRole("button", { name: /printing needs review/i });
    fireEvent.click(statusButton);

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });
    expect(getActivePrintSessionSnapshot().recoveryRequestId).toBe(0);
  });
});
