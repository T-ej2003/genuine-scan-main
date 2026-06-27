import { createHash } from "crypto";

import { MSCQR_WORDMARK_ZPL_GRAPHIC } from "./generated/brandWordmarkZpl";

export const ZPL_300DPI_GENERIC_PROFILE_ID = "zpl_300dpi_generic";
export const ZEBRA_ZT410_300DPI_PROFILE_ID = "zebra_zt410_300dpi";
export const UNSUPPORTED_NON_ZPL_PROFILE_ID = "unsupported_non_zpl";

export const ZPL_300DPI_COMPATIBILITY_CONTRACT = {
  profileId: ZPL_300DPI_GENERIC_PROFILE_ID,
  compatiblePrinterProfile: ZPL_300DPI_GENERIC_PROFILE_ID,
  requiredLanguage: "ZPL",
  requiredDpi: 300,
  labelWidthDots: 472,
  labelHeightDots: 591,
  maxPayloadBytes: 12_000,
  maxGraphicFields: 1,
  allowedBrandBox: {
    xMin: 0,
    yMin: 8,
    xMax: 205,
    yMax: 28,
    widthDots: MSCQR_WORDMARK_ZPL_GRAPHIC.widthDots,
    heightDots: MSCQR_WORDMARK_ZPL_GRAPHIC.heightDots,
  },
  qrBox: {
    xMin: 12,
    yMin: 118,
    xMax: 420,
    yMax: 468,
    quietZoneDots: 28,
  },
  serialTextBox: {
    xMin: 0,
    yMin: 520,
    xMax: 472,
    yMax: 588,
  },
  darknessSafeBounds: {
    min: 0,
    max: 30,
  },
} as const;

export const OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT = {
  id: "mscqr_official_wordmark_v1",
  zplCommand: "^GFA",
  widthDots: MSCQR_WORDMARK_ZPL_GRAPHIC.widthDots,
  heightDots: MSCQR_WORDMARK_ZPL_GRAPHIC.heightDots,
  bytesPerRow: MSCQR_WORDMARK_ZPL_GRAPHIC.bytesPerRow,
  totalBytes: MSCQR_WORDMARK_ZPL_GRAPHIC.totalBytes,
  dataSha256: "d5707dfffaa6c4a614db9ecdbba27505134d36bf904f664d5b2d85656994f854",
  normalizedGraphicSha256: "a7926928e5e8d2cce6767620ebe7ec4c89c7a3e8c29bf519bbaf6122e979cf6a",
  maxBytes: 2040,
} as const;

export const buildOfficialMscqrWordmarkGraphicHashInput = (graphic: {
  widthDots: number;
  heightDots: number;
  bytesPerRow: number;
  totalBytes: number;
  data: string;
}) => `${graphic.widthDots}:${graphic.heightDots}:${graphic.bytesPerRow}:${graphic.totalBytes}:${graphic.data}`;

export const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

export const getOfficialMscqrWordmarkGraphicHash = () =>
  sha256Hex(buildOfficialMscqrWordmarkGraphicHashInput(MSCQR_WORDMARK_ZPL_GRAPHIC));

export const getOfficialMscqrWordmarkDataHash = () => sha256Hex(MSCQR_WORDMARK_ZPL_GRAPHIC.data);

export const assertOfficialMscqrWordmarkContractCurrent = () => {
  const normalizedGraphicSha256 = getOfficialMscqrWordmarkGraphicHash();
  const dataSha256 = getOfficialMscqrWordmarkDataHash();
  if (normalizedGraphicSha256 !== OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.normalizedGraphicSha256) {
    throw new Error("Official MSCQR ZPL wordmark normalized graphic hash drifted.");
  }
  if (dataSha256 !== OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.dataSha256) {
    throw new Error("Official MSCQR ZPL wordmark data hash drifted.");
  }
  return true;
};

export const buildOfficialMscqrWordmarkGfaCommand = () =>
  `^GFA,${MSCQR_WORDMARK_ZPL_GRAPHIC.totalBytes},${MSCQR_WORDMARK_ZPL_GRAPHIC.totalBytes},${MSCQR_WORDMARK_ZPL_GRAPHIC.bytesPerRow},${MSCQR_WORDMARK_ZPL_GRAPHIC.data}`;

export const isZplCompatibleLanguageList = (languages: Array<string | null | undefined>) =>
  languages.some((value) => {
    const normalized = String(value || "").trim().toUpperCase();
    return normalized === "ZPL" || normalized === "ZPL2" || normalized === "ZPL-II" || normalized === "ZSIM";
  });

export const inferZplPrinterDpi = (...values: unknown[]) => {
  const combined = values.map((value) => String(value || "")).join(" ");
  const match = combined.match(/(\d{3,4})\s*dpi/i);
  const dpi = Number(match?.[1] || 0);
  return Number.isInteger(dpi) && dpi > 0 ? dpi : null;
};

export const classifyIndustrialZplPrinterProfile = (params: {
  printerName?: string | null;
  model?: string | null;
  languages?: Array<string | null | undefined> | null;
  printerLanguages?: Array<string | null | undefined> | null;
  dpi?: number | null;
  printerDpi?: number | null;
}) => {
  const languages = Array.isArray(params.languages)
    ? params.languages
    : Array.isArray(params.printerLanguages)
      ? params.printerLanguages
      : [];
  const combined = `${params.printerName || ""} ${params.model || ""} ${languages.join(" ")}`;
  const isZpl = isZplCompatibleLanguageList(languages) || /\bZPL(?:-?II|2)?\b/i.test(combined) || /\bZSIM\b/i.test(combined);
  if (!isZpl) return { profileId: UNSUPPORTED_NON_ZPL_PROFILE_ID, compatible: false, reason: "unsupported_printer_language" };

  const rawDpi = params.dpi ?? params.printerDpi;
  const dpi = Number.isFinite(Number(rawDpi)) ? Number(rawDpi) : inferZplPrinterDpi(combined);
  if (dpi && dpi !== ZPL_300DPI_COMPATIBILITY_CONTRACT.requiredDpi) {
    return { profileId: "zpl_unsupported_dpi", compatible: false, reason: "unsupported_printer_dpi", dpi };
  }

  return { profileId: ZPL_300DPI_GENERIC_PROFILE_ID, compatible: true, reason: null, dpi: dpi || 300 };
};
