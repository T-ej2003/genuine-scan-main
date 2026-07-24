import React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import { BrandLockup } from "@/components/brand/BrandLockup";
import { MscqrLogo } from "@/components/brand/MscqrLogo";
import indexHtml from "../../index.html?raw";
import manifestText from "../../public/site.webmanifest?raw";

describe("MSCQR brand assets", () => {
  it("renders the official wordmark and mark asset paths", () => {
    render(<MscqrLogo variant="wordmark" alt="MSCQR" className="h-6" />);

    const wordmark = screen.getByRole("img", { name: "MSCQR" });
    expect(wordmark).toHaveAttribute("src", "/brand/mscqr-wordmark.svg");
    expect(wordmark).toHaveAttribute("loading", "eager");
    expect(wordmark).toHaveAttribute("decoding", "async");
  });

  it("uses image assets for the reusable lockup instead of system-font MSCQR text", () => {
    render(
      <MemoryRouter>
        <BrandLockup to="/" ariaLabel="MSCQR home" />
      </MemoryRouter>,
    );

    const link = screen.getByRole("link", { name: "MSCQR home" });
    expect(link.querySelector('img[src="/brand/mscqr-logo-mark.svg"]')).toBeTruthy();
    expect(link.querySelector('img[src="/brand/mscqr-wordmark.svg"]')).toBeTruthy();
    expect(link).not.toHaveTextContent(/^MSCQR$/);
  });

  it("keeps favicon, manifest, and JSON-LD paths on generated official assets", () => {
    const manifest = JSON.parse(manifestText);

    expect(indexHtml).toContain('href="/favicon.svg"');
    expect(indexHtml).toContain('"logo": "https://www.mscqr.com/brand/mscqr-logo-mark-512.png"');
    expect(indexHtml).toContain('content="https://www.mscqr.com/brand/mscqr-og.png"');
    expect(manifest.icons.map((icon: { src: string }) => icon.src)).toEqual(
      expect.arrayContaining([
        "/favicon-48x48.png",
        "/android-chrome-192x192.png",
        "/android-chrome-512x512.png",
        "/brand/mscqr-logo-mark-512.png",
      ]),
    );
  });
});
