import { PrinterLanguageKind, PrintPayloadType } from "@prisma/client";

import type { CanonicalLabelDocument } from "../canonicalLabel";

export type RenderedPrinterPayload = {
  payloadType: PrintPayloadType;
  payloadContent: string;
};

export type PrinterLanguageRenderer = {
  language: PrinterLanguageKind;
  render: (document: CanonicalLabelDocument, params: { dpi?: number | null }) => RenderedPrinterPayload;
};

const mmToDots = (mm: number, dpi = 300) => Math.round((mm / 25.4) * dpi);

const renderZpl = (document: CanonicalLabelDocument, params: { dpi?: number | null }): RenderedPrinterPayload => {
  const dpi = params.dpi || document.densityHintDpi || 300;
  const width = mmToDots(document.widthMm, dpi);
  const height = mmToDots(document.heightMm, dpi);
  const qr = document.blocks.find((block) => block.type === "qr");
  const qrWidth = qr && "widthMm" in qr ? mmToDots(qr.widthMm, dpi) : Math.max(240, Math.min(width, height) - 32);
  const qrLeft = qr ? mmToDots(qr.xMm, dpi) : 16;
  const qrTop = qr ? mmToDots(qr.yMm, dpi) : 16;
  const cellSize = Math.max(4, Math.min(10, Math.round(width / 75)));
  const scanUrl = qr && qr.type === "qr" ? qr.payload.scanUrl : document.qrReference.scanUrl;

  return {
    payloadType: PrintPayloadType.ZPL,
    payloadContent: ["^XA", `^PW${width}`, `^LL${height}`, "^LH0,0", "^CI28", `^FO${qrLeft},${qrTop}^BQN,2,${cellSize}^FDLA,${scanUrl}^FS`, "^XZ"].join("\n"),
  };
};

const renderTspl = (document: CanonicalLabelDocument, params: { dpi?: number | null }): RenderedPrinterPayload => {
  const dpi = params.dpi || document.densityHintDpi || 300;
  const qr = document.blocks.find((block) => block.type === "qr");
  const scanUrl = qr && qr.type === "qr" ? qr.payload.scanUrl : document.qrReference.scanUrl;
  return {
    payloadType: PrintPayloadType.TSPL,
    payloadContent: [
      `SIZE ${document.widthMm} mm,${document.heightMm} mm`,
      "GAP 3 mm,0 mm",
      "DIRECTION 1",
      "CLS",
      `QRCODE ${mmToDots(qr?.xMm || 2, dpi)},${mmToDots(qr?.yMm || 2, dpi)},L,6,A,0,M2,S7,\"${scanUrl}\"`,
      "PRINT 1,1",
    ].join("\n"),
  };
};

const renderEpl = (document: CanonicalLabelDocument, params: { dpi?: number | null }): RenderedPrinterPayload => {
  const dpi = params.dpi || document.densityHintDpi || 300;
  const width = mmToDots(document.widthMm, dpi);
  const height = mmToDots(document.heightMm, dpi);
  const scanUrl = document.qrReference.scanUrl;
  return {
    payloadType: PrintPayloadType.EPL,
    payloadContent: ["N", `q${width}`, `Q${height},24`, `b16,16,Q,m2,s6,eM,A,\"${scanUrl}\"`, "P1"].join("\n"),
  };
};

const renderCpcl = (document: CanonicalLabelDocument, params: { dpi?: number | null }): RenderedPrinterPayload => {
  const dpi = params.dpi || document.densityHintDpi || 300;
  const width = mmToDots(document.widthMm, dpi);
  const height = mmToDots(document.heightMm, dpi);
  const scanUrl = document.qrReference.scanUrl;
  return {
    payloadType: PrintPayloadType.CPCL,
    payloadContent: [`! 0 200 200 ${height} 1`, `PW ${width}`, "B QR 16 16 M 2 U 6", `MA,${scanUrl}`, "ENDQR", "FORM", "PRINT"].join("\n"),
  };
};

const renderSbpl = (document: CanonicalLabelDocument): RenderedPrinterPayload => {
  const scanUrl = document.qrReference.scanUrl;
  return {
    payloadType: PrintPayloadType.SBPL,
    payloadContent: [`<ESC>A`, `<ESC>H0100`, `<ESC>V0100`, `<ESC>2D30,${scanUrl}`, `<ESC>Q1`, `<ESC>Z`].join("\n"),
  };
};

const renderJson = (document: CanonicalLabelDocument): RenderedPrinterPayload => ({
  payloadType: PrintPayloadType.JSON,
  payloadContent: JSON.stringify(document),
});

export const PRINTER_LANGUAGE_RENDERERS: Record<string, PrinterLanguageRenderer> = {
  [PrinterLanguageKind.ZPL]: { language: PrinterLanguageKind.ZPL, render: renderZpl },
  [PrinterLanguageKind.TSPL]: { language: PrinterLanguageKind.TSPL, render: renderTspl },
  [PrinterLanguageKind.EPL]: { language: PrinterLanguageKind.EPL, render: renderEpl },
  [PrinterLanguageKind.DPL]: { language: PrinterLanguageKind.DPL, render: renderCpcl },
  [PrinterLanguageKind.HONEYWELL_DP]: { language: PrinterLanguageKind.HONEYWELL_DP, render: renderCpcl },
  [PrinterLanguageKind.HONEYWELL_FINGERPRINT]: { language: PrinterLanguageKind.HONEYWELL_FINGERPRINT, render: renderCpcl },
  [PrinterLanguageKind.IPL]: { language: PrinterLanguageKind.IPL, render: renderCpcl },
  [PrinterLanguageKind.SBPL]: { language: PrinterLanguageKind.SBPL, render: renderSbpl },
  [PrinterLanguageKind.ZSIM]: { language: PrinterLanguageKind.ZSIM, render: renderZpl },
  [PrinterLanguageKind.AUTO]: { language: PrinterLanguageKind.AUTO, render: renderJson },
  [PrinterLanguageKind.PDF]: { language: PrinterLanguageKind.PDF, render: renderJson },
  [PrinterLanguageKind.OTHER]: { language: PrinterLanguageKind.OTHER, render: renderJson },
};

export const resolvePrinterLanguageRenderer = (language: PrinterLanguageKind) =>
  PRINTER_LANGUAGE_RENDERERS[language] || PRINTER_LANGUAGE_RENDERERS[PrinterLanguageKind.AUTO];
