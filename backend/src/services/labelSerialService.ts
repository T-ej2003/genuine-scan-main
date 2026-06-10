import { createHash } from "crypto";

type MetadataCarrier = {
  metadata?: unknown;
  name?: string | null;
  prefix?: string | null;
  location?: string | null;
  nativePrinterId?: string | null;
};

export type LabelSerialContext = {
  qrId: string;
  sequence?: number | null;
  issuedAt?: Date | string | null;
  batch?: MetadataCarrier | null;
  licensee?: MetadataCarrier | null;
  manufacturer?: MetadataCarrier | null;
  printer?: MetadataCarrier | null;
};

export type GeneratedLabelSerial = {
  humanSerial: string;
  regionCode: string;
  brandCode: string;
  factoryCode: string;
  lineCode: string;
  yearCode: string;
  sequence: number;
  check: string;
  warnings: string[];
};

const FALLBACKS = {
  regionCode: "RGN",
  brandCode: "BRD",
  factoryCode: "FAC",
  lineCode: "L00",
};

const metadataRecord = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
};

const firstString = (...values: unknown[]) => {
  for (const value of values) {
    const trimmed = String(value || "").trim();
    if (trimmed) return trimmed;
  }
  return "";
};

const segment = (value: string, fallback: string, max = 6) => {
  const cleaned = value
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, max);
  return cleaned || fallback;
};

const compactNameCode = (value: string, fallback: string) => {
  const words = value
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .map((word) => word.trim())
    .filter(Boolean);
  if (words.length >= 2) return segment(words.map((word) => word[0]).join(""), fallback, 3);
  return segment(value, fallback, 3);
};

const readCode = (carrier: MetadataCarrier | null | undefined, keys: string[], fallback: string, max = 6) => {
  const metadata = metadataRecord(carrier?.metadata);
  return segment(firstString(...keys.map((key) => metadata[key]), carrier?.prefix, carrier?.name, carrier?.location), fallback, max);
};

const readLineCode = (printer: MetadataCarrier | null | undefined) => {
  const metadata = metadataRecord(printer?.metadata);
  return segment(firstString(metadata.lineCode, metadata.productionLineCode, metadata.productionLine, printer?.nativePrinterId), FALLBACKS.lineCode, 4);
};

const yearCode = (value?: Date | string | null) => {
  const date = value ? new Date(value) : new Date();
  const year = Number.isFinite(date.getTime()) ? date.getUTCFullYear() : new Date().getUTCFullYear();
  return String(year % 100).padStart(2, "0");
};

const checksum = (parts: string[]) =>
  createHash("sha256")
    .update(parts.join("|"))
    .digest("base64url")
    .replace(/[^A-Z0-9]/gi, "")
    .toUpperCase()
    .slice(0, 3)
    .padEnd(3, "X");

export const generateHumanLabelSerial = (context: LabelSerialContext): GeneratedLabelSerial => {
  const licenseeMeta = metadataRecord(context.licensee?.metadata);
  const batchMeta = metadataRecord(context.batch?.metadata);
  const manufacturerMeta = metadataRecord(context.manufacturer?.metadata);
  const printerMeta = metadataRecord(context.printer?.metadata);

  const regionCode = segment(
    firstString(batchMeta.regionCode, licenseeMeta.regionCode, manufacturerMeta.regionCode, printerMeta.regionCode, context.licensee?.location),
    FALLBACKS.regionCode,
    4
  );
  const brandCode =
    segment(firstString(licenseeMeta.serialCode, licenseeMeta.brandCode, context.licensee?.prefix), "", 4) ||
    compactNameCode(firstString(context.licensee?.name), FALLBACKS.brandCode);
  const factoryCode =
    segment(firstString(manufacturerMeta.factoryCode, manufacturerMeta.serialCode), "", 4) ||
    compactNameCode(firstString(context.manufacturer?.name, context.manufacturer?.location), FALLBACKS.factoryCode);
  const lineCode = readLineCode(context.printer);
  const year = yearCode(context.issuedAt);
  const sequence = Math.max(1, Math.floor(Number(context.sequence || 1)));
  const sequenceText = String(sequence).padStart(6, "0");
  const check = checksum([regionCode, brandCode, factoryCode, lineCode, year, sequenceText, context.qrId]);
  const warnings = [
    regionCode === FALLBACKS.regionCode ? "missing_region_code" : "",
    brandCode === FALLBACKS.brandCode ? "missing_brand_code" : "",
    factoryCode === FALLBACKS.factoryCode ? "missing_factory_code" : "",
    lineCode === FALLBACKS.lineCode ? "missing_line_code" : "",
  ].filter(Boolean);

  return {
    humanSerial: `${regionCode}-${brandCode}-${factoryCode}-${lineCode}-${year}-${sequenceText}-${check}`,
    regionCode,
    brandCode,
    factoryCode,
    lineCode,
    yearCode: year,
    sequence,
    check,
    warnings,
  };
};
