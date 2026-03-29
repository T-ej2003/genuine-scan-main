import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import ConnectorDownload from "@/pages/ConnectorDownload";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    getLatestConnectorRelease: vi.fn(),
    getInvitePreview: vi.fn(),
  },
}));

describe("ConnectorDownload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.3.12",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.3.12",
          publishedAt: "2026-03-12T20:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: {
              platform: "macos",
              label: "macOS installer",
              installerKind: "pkg",
              filename: "MSCQR-Connector-macOS-2026.3.12.pkg",
              architecture: "universal (arm64 + x64)",
              bytes: 1024,
              sha256: "a".repeat(64),
              notes: ["Double-click the pkg file once."],
              contentType: "application/octet-stream",
              downloadPath: "/api/public/connector/download/2026.3.12/macos",
              downloadUrl: "https://example.test/api/public/connector/download/2026.3.12/macos",
            },
            windows: {
              platform: "windows",
              label: "Windows package",
              installerKind: "zip",
              filename: "MSCQR-Connector-Windows-2026.3.12.zip",
              architecture: "x64",
              bytes: 2048,
              sha256: "b".repeat(64),
              notes: ["Run Install Connector.cmd once."],
              contentType: "application/zip",
              downloadPath: "/api/public/connector/download/2026.3.12/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.3.12/windows",
            },
          },
        },
      },
    } as any);
  });

  it("shows the latest installer choices and onboarding copy", async () => {
    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({
      success: true,
      data: {
        email: "factory@example.com",
        role: "MANUFACTURER",
        expiresAt: "2026-03-13T20:00:00.000Z",
        licenseeName: "Acme Factory 1",
        requiresConnector: true,
      },
    } as any);

    render(
      <MemoryRouter initialEntries={["/connector-download?inviteToken=sample-token-123456"]}>
        <ConnectorDownload />
      </MemoryRouter>
    );

    expect(await screen.findByText("Install printer helper")).toBeInTheDocument();
    expect(screen.getByText(/Acme Factory 1/i)).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: /download for mac/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/macos",
    );
    expect(await screen.findByRole("link", { name: /download for windows/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/windows",
    );
    expect(screen.getByText(/Extract the ZIP fully before running/i)).toBeInTheDocument();
    expect(screen.getByText(/Run the installer once/i)).toBeInTheDocument();
    expect(screen.getAllByText(/checks whether the local printer is really ready/i).length).toBeGreaterThan(0);
  });

  it("repairs legacy connector links that still point at /public instead of /api/public", async () => {
    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({ success: false, error: "No invite" } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.3.12",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.3.12",
          publishedAt: "2026-03-12T20:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: {
              platform: "macos",
              label: "macOS installer",
              installerKind: "pkg",
              filename: "MSCQR-Connector-macOS-2026.3.12.pkg",
              architecture: "universal (arm64 + x64)",
              bytes: 1024,
              sha256: "a".repeat(64),
              notes: ["Double-click the pkg file once."],
              contentType: "application/octet-stream",
              downloadPath: "/public/connector/download/2026.3.12/macos",
              downloadUrl: "https://example.test/public/connector/download/2026.3.12/macos",
            },
            windows: {
              platform: "windows",
              label: "Windows package",
              installerKind: "zip",
              filename: "MSCQR-Connector-Windows-2026.3.12.zip",
              architecture: "x64",
              bytes: 2048,
              sha256: "b".repeat(64),
              notes: ["Run Install Connector.cmd once."],
              contentType: "application/zip",
              downloadPath: "/public/connector/download/2026.3.12/windows",
              downloadUrl: "https://example.test/public/connector/download/2026.3.12/windows",
            },
          },
        },
      },
    } as any);

    render(
      <MemoryRouter initialEntries={["/connector-download"]}>
        <ConnectorDownload />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("link", { name: /download for mac/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/macos",
    );
    expect(await screen.findByRole("link", { name: /download for windows/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/windows",
    );
  });

  it("renders the page when the latest release has no published macOS package", async () => {
    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({ success: false, error: "No invite" } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.3.12",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.3.12",
          publishedAt: "2026-03-12T20:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: null,
            windows: {
              platform: "windows",
              label: "Windows package",
              installerKind: "zip",
              filename: "MSCQR-Connector-Windows-2026.3.12.zip",
              architecture: "x64",
              bytes: 2048,
              sha256: "b".repeat(64),
              notes: ["Run Install Connector.cmd once."],
              contentType: "application/zip",
              downloadPath: "/api/public/connector/download/2026.3.12/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.3.12/windows",
            },
          },
        },
      },
    } as any);

    render(
      <MemoryRouter initialEntries={["/connector-download"]}>
        <ConnectorDownload />
      </MemoryRouter>,
    );

    expect(screen.queryByRole("link", { name: /download for mac/i })).not.toBeInTheDocument();
    expect(await screen.findByRole("link", { name: /download for windows/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/windows",
    );
  });

  it("does not offer the Windows installer as the detected-device download on a Mac when no signed Mac package is published", async () => {
    const userAgentSpy = vi
      .spyOn(window.navigator, "userAgent", "get")
      .mockReturnValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
    const platformSpy = vi.spyOn(window.navigator, "platform", "get").mockReturnValue("MacIntel");

    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({ success: false, error: "No invite" } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.3.12",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.3.12",
          publishedAt: "2026-03-12T20:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: null,
            windows: {
              platform: "windows",
              label: "Windows package",
              installerKind: "zip",
              filename: "MSCQR-Connector-Windows-2026.3.12.zip",
              architecture: "x64",
              bytes: 2048,
              sha256: "b".repeat(64),
              notes: ["Run Install Connector.cmd once."],
              contentType: "application/zip",
              downloadPath: "/api/public/connector/download/2026.3.12/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.3.12/windows",
            },
          },
        },
      },
    } as any);

    render(
      <MemoryRouter initialEntries={["/connector-download"]}>
        <ConnectorDownload />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/signed Mac installer not published yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /get installer for this device/i })).not.toBeInTheDocument();
    expect(await screen.findByRole("link", { name: /download for windows/i })).toHaveAttribute(
      "href",
      "https://example.test/api/public/connector/download/2026.3.12/windows",
    );

    userAgentSpy.mockRestore();
    platformSpy.mockRestore();
  });
});
