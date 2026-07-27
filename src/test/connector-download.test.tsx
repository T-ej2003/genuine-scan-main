import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import ConnectorDownload from "@/pages/ConnectorDownload";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    getLatestConnectorRelease: vi.fn(),
    getInvitePreview: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
  },
}));

const expectAllLinksToMatch = (links: HTMLElement[], href: string) => {
  expect(links.length).toBeGreaterThan(0);
  for (const link of links) {
    expect(link).toHaveAttribute("href", href);
  }
};

describe("ConnectorDownload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        agentVersion: "2026.5.19",
        buildVersion: "2026.5.19",
        protocolVersion: "local-agent-direct-v2",
      },
    } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.5.19",
        requiredProtocolVersion: "local-agent-direct-v2",
        minimumBuildVersion: "2026.5.19",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.5.19",
          publishedAt: "2026-05-19T00:00:00.000Z",
          requiredProtocolVersion: "local-agent-direct-v2",
          minimumBuildVersion: "2026.5.19",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: {
              platform: "macos",
              label: "macOS installer",
              installerKind: "pkg",
              trustLevel: "trusted",
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
              label: "Windows installer",
              installerKind: "exe",
              artifactType: "windows-signed-installer",
              trustLevel: "production",
              signatureStatus: "signed",
              smartAppControlSafe: true,
              publisherName: "L&D Health Ltd",
              signedAt: "2026-05-19T00:00:00.000Z",
              signatureSubject: "CN=L&D Health Ltd",
              signatureIssuer: "CN=Microsoft Trusted Signing",
              certificateThumbprint: "thumbprint",
              timestamped: true,
              windowsTrustMode: "trusted",
              filename: "MSCQR-Connector-Windows-2026.5.19.exe",
              architecture: "x64",
              bytes: 15587056,
              sha256: "0305cc85fe1af4ff65f87d584028d03745b6b70a227100d2f13f9ebe234e2d41",
              protocolVersion: "local-agent-direct-v2",
              buildVersion: "2026.5.19",
              legalDocumentsIncluded: ["legal/EULA.txt", "legal/PRIVACY_POLICY.txt"],
              releaseNotesIncluded: true,
              notes: ["Run the signed Windows installer once."],
              contentType: "application/vnd.microsoft.portable-executable",
              downloadPath: "/api/public/connector/download/2026.5.19/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.5.19/windows",
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
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download for mac/i }),
      "https://example.test/api/public/connector/download/2026.3.12/macos",
    );
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download windows installer/i }),
      "https://example.test/api/public/connector/download/2026.5.19/windows",
    );
    expect(screen.getByText(/Run the installer once/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Signed Windows installer/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/L&D Health Ltd/i)).toBeInTheDocument();
    expect(screen.getByText(/Azure Trusted Signing \/ signed/i)).toBeInTheDocument();
    expect(screen.getByText(/Legal documents included/i)).toBeInTheDocument();
    expect(screen.getAllByText(/local-agent-direct-v2/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Update required/i)).toBeInTheDocument();
    expect(screen.getByText(/^No$/i)).toBeInTheDocument();
    expect(screen.queryByText(/Windows can block this unsigned test package/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Extract the ZIP fully before running/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Unsigned test package/i)).not.toBeInTheDocument();
    expect(screen.getAllByText(/verifies local printer readiness before it tells you setup is complete/i).length).toBeGreaterThan(0);
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
              trustLevel: "trusted",
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
              label: "Windows installer",
              installerKind: "exe",
              trustLevel: "production",
              signatureStatus: "signed",
              publisherName: "L&D Health Ltd",
              signedAt: "2026-03-12T20:00:00.000Z",
              windowsTrustMode: "trusted",
              filename: "MSCQR-Connector-Windows-2026.3.12.exe",
              architecture: "x64",
              bytes: 2048000,
              sha256: "b".repeat(64),
              notes: ["Run the signed Windows installer once."],
              contentType: "application/vnd.microsoft.portable-executable",
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

    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download for mac/i }),
      "https://example.test/api/public/connector/download/2026.3.12/macos",
    );
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download windows installer/i }),
      "https://example.test/api/public/connector/download/2026.3.12/windows",
    );
  });

  it("renders the page when the latest release has no published macOS package", async () => {
    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({ success: false, error: "No invite" } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        productName: "MSCQR Connector",
        latestVersion: "2026.5.19",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.5.19",
          publishedAt: "2026-05-19T00:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: null,
            windows: {
              platform: "windows",
              label: "Windows installer",
              installerKind: "exe",
              trustLevel: "trusted",
              signatureStatus: "signed",
              publisherName: "L&D Health Ltd",
              signedAt: "2026-05-19T00:00:00.000Z",
              windowsTrustMode: "trusted",
              filename: "MSCQR-Connector-Windows-2026.5.19.exe",
              architecture: "x64",
              bytes: 15587056,
              sha256: "0305cc85fe1af4ff65f87d584028d03745b6b70a227100d2f13f9ebe234e2d41",
              notes: ["Run the signed Windows installer once."],
              contentType: "application/vnd.microsoft.portable-executable",
              downloadPath: "/api/public/connector/download/2026.5.19/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.5.19/windows",
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
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download windows installer/i }),
      "https://example.test/api/public/connector/download/2026.5.19/windows",
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
        latestVersion: "2026.5.19",
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        release: {
          version: "2026.5.19",
          publishedAt: "2026-05-19T00:00:00.000Z",
          summary: "Install once and print without manual startup.",
          notes: [],
          platforms: {
            macos: null,
            windows: {
              platform: "windows",
              label: "Windows installer",
              installerKind: "exe",
              trustLevel: "trusted",
              signatureStatus: "signed",
              publisherName: "L&D Health Ltd",
              signedAt: "2026-05-19T00:00:00.000Z",
              windowsTrustMode: "trusted",
              filename: "MSCQR-Connector-Windows-2026.5.19.exe",
              architecture: "x64",
              bytes: 15587056,
              sha256: "0305cc85fe1af4ff65f87d584028d03745b6b70a227100d2f13f9ebe234e2d41",
              notes: ["Run the signed Windows installer once."],
              contentType: "application/vnd.microsoft.portable-executable",
              downloadPath: "/api/public/connector/download/2026.5.19/windows",
              downloadUrl: "https://example.test/api/public/connector/download/2026.5.19/windows",
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
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download windows installer/i }),
      "https://example.test/api/public/connector/download/2026.5.19/windows",
    );

    userAgentSpy.mockRestore();
    platformSpy.mockRestore();
  });

  it("keeps unsigned Windows ZIPs in the internal validation panel", async () => {
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
            windows: null,
            windowsUnsignedTest: {
              platform: "windowsUnsignedTest",
              label: "Windows test package",
              installerKind: "zip",
              artifactType: "windows-unsigned-test-zip",
              trustLevel: "internal-test",
              signatureStatus: "unsigned",
              smartAppControlSafe: false,
              publisherName: null,
              signedAt: null,
              windowsTrustMode: "unsigned-test",
              internalOnly: true,
              filename: "MSCQR-Connector-Windows-2026.3.12.zip",
              architecture: "x64",
              bytes: 4096000,
              sha256: "c".repeat(64),
              notes: ["Run this Windows test package only for internal verification."],
              contentType: "application/zip",
              downloadPath: "/api/public/connector/download/2026.3.12/windowsUnsignedTest",
              downloadUrl: "https://example.test/api/public/connector/download/2026.3.12/windowsUnsignedTest",
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

    expect(await screen.findByText(/Signed connector release is not available yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /download windows test package/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(/Internal validation package/i));
    expectAllLinksToMatch(
      await screen.findAllByRole("link", { name: /download internal zip/i }),
      "https://example.test/api/public/connector/download/2026.3.12/windowsUnsignedTest",
    );
    expect(screen.getByText(/Do not use it for production factory rollout/i)).toBeInTheDocument();
  });

  it("shows update required when an installed connector reports a stale protocol", async () => {
    vi.mocked(apiClient.getInvitePreview).mockResolvedValue({ success: false, error: "No invite" } as any);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        agentVersion: "2026.5.10",
        buildVersion: "2026.5.10",
        protocolVersion: "test.v1#4",
      },
    } as any);

    render(
      <MemoryRouter initialEntries={["/connector-download"]}>
        <ConnectorDownload />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/2026\.5\.10/i)).toBeInTheDocument();
    expect(screen.getByText(/Update required/i)).toBeInTheDocument();
    expect(screen.getByText(/^Yes$/i)).toBeInTheDocument();
  });
});
