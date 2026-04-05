import type { CreateLicenseeForm } from "@/features/licensees/types";

export const LARGE_QR_ALLOCATION_THRESHOLD = 25_000;

export const isValidPrefix = (prefix: string) => /^[A-Z0-9]{1,5}$/.test(prefix);

export const toInt = (value: string) => {
  const parsed = parseInt(String(value || "").trim(), 10);
  return Number.isFinite(parsed) ? parsed : NaN;
};

export const extractCodeIndex = (code?: string | null) => {
  const normalized = String(code || "").trim();
  if (!normalized) return null;
  const match = normalized.match(/(\d{10})$/);
  if (!match) return null;
  const parsed = parseInt(match[1], 10);
  return Number.isFinite(parsed) ? parsed : null;
};

export const isBusyErrorMessage = (message?: string) => {
  const normalized = (message || "").toLowerCase();
  return normalized.includes("batch busy") || normalized.includes("retry") || normalized.includes("conflict");
};

export const createDefaultLicenseeForm = (): CreateLicenseeForm => ({
  name: "",
  prefix: "A",
  description: "",
  isActive: true,
  brandName: "",
  location: "",
  website: "",
  supportEmail: "",
  supportPhone: "",
  adminName: "",
  adminEmail: "",
  rangeStart: "1",
  rangeEnd: "150000",
  createManufacturerNow: true,
  manufacturerName: "",
  manufacturerEmail: "",
});
