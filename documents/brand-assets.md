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

Production ZPL labels embed that bounded graphic with `^GFA` for the visual wordmark, while keeping QR sizing, quiet zone, scan URL, and serial text under the existing print payload safety checks.
