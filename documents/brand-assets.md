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

Production 300dpi ZPL labels embed the official wordmark as a bounded one-bit `^GFA` graphic. This is required because industrial ZPL printers cannot reproduce the stylised MSCQR wordmark with plain `^FDMSCQR^FS` text unless a custom font or graphic is installed on each printer.

The generated graphic is allowed only through the shared 300dpi ZPL compatibility contract in:

- `backend/src/printing/zplCompatibilityContract.ts`

Current contract:

- Profile: `zpl_300dpi_generic`
- Label: `40x50mm`, `300dpi`, `472x591` dots
- Official graphic: `mscqr_official_wordmark_v1`
- Graphic data hash: `d5707dfffaa6c4a614db9ecdbba27505134d36bf904f664d5b2d85656994f854`
- Normalized graphic hash: `a7926928e5e8d2cce6767620ebe7ec4c89c7a3e8c29bf519bbaf6122e979cf6a`
- Connector requirement: MSCQR Connector `2026.6.26` or newer

Backend and connector safety both reject arbitrary, repeated, oversized, mutated, or out-of-bounds `^GF/^GFA` payloads. Printers must be confirmed as 300dpi ZPL/ZPL-II compatible; non-ZPL queues and unsupported DPI profiles are rejected before print.
