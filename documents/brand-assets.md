# MSCQR Brand Assets

MSCQR uses the official MSCQR-owned SVG assets as the source of truth for visual branding.

## Source Assets

- Wordmark: `public/brand/mscqr-wordmark.svg`
- Logo mark/icon: `public/brand/mscqr-logo-mark.svg`

Use the wordmark wherever the product logo is rendered visually. Keep plain text `MSCQR` where the name is semantic copy, accessibility text, legal text, SEO metadata, route labels, audit entries, API payloads, or email/plain-text fallback content.

## Derived Web Assets

The deterministic derived assets are generated locally from the official SVG files:

- Favicons: `public/favicon.ico`, `public/favicon.svg`, `public/favicon-16x16.png`, `public/favicon-32x32.png`, `public/favicon-48x48.png`
- App icons: `public/apple-touch-icon.png`, `public/android-chrome-192x192.png`, `public/android-chrome-512x512.png`
- Metadata images: `public/brand/mscqr-logo-mark-512.png`, `public/brand/mscqr-og.png`
- Legacy-compatible mark paths: `public/brand/mscqr-mark.svg`, `public/brand/mscqr-mark-512.png`

Regenerate them with:

```sh
node scripts/generate-brand-assets.mjs
```

The generator uses the repo's Playwright dependency and does not call external services.

## Print Label Asset

Zebra ZPL cannot print raw SVG directly. The same generator converts `public/brand/mscqr-wordmark.svg` into a small one-bit ZPL graphic module at:

- `backend/src/printing/generated/brandWordmarkZpl.ts`

Production Zebra ZPL labels currently do not embed the `^GFA` wordmark graphic. The hardware connector safety profile rejects raster graphics before spooler dispatch in the active ZDesigner ZT410-300dpi ZPL launch profile, so production ZPL temporarily uses the safety-approved semantic `MSCQR` text header. This keeps QR sizing, quiet zone, scan URL, serial text, and connector trust unchanged while preventing false "started printing" states.

The generated wordmark module remains in source control for future hardware validation. Re-enable it only after the backend safety profile, packaged connector safety profile, diagnostic label path, and physical Zebra validation all accept the same bounded official graphic while continuing to reject arbitrary or oversized `^GF/^GFA` payloads.
