import { format } from "date-fns";

export type LicenseeOption = {
  id: string;
  name: string;
  prefix: string;
};

export type ManufacturerRow = {
  id: string;
  name: string;
  email: string;
  isActive: boolean;
  createdAt?: string;
  licenseeId?: string;
  location?: string | null;
  website?: string | null;
};

export type CreateManufacturerValues = {
  licenseeId: string;
  name: string;
  email: string;
  location: string;
  website: string;
};

export type BatchRow = {
  id: string;
  name: string;
  licenseeId?: string;
  manufacturerId?: string | null;
  totalCodes?: number;
  availableCodes?: number;
  printedAt?: string | null;
  createdAt?: string;
  startCode?: string;
  endCode?: string;
};

export type ManufacturerStats = {
  assignedBatches: number;
  assignedCodes: number;
  printedBatches: number;
  pendingPrintBatches: number;
  lastBatchAt: string | null;
  recentBatches: BatchRow[];
};

export type ManufacturerDirectoryData = {
  manufacturers: ManufacturerRow[];
  statsById: Record<string, ManufacturerStats>;
};

const asRecord = (value: unknown) => (value && typeof value === "object" ? (value as Record<string, unknown>) : null);

export const emptyManufacturerStats = (): ManufacturerStats => ({
  assignedBatches: 0,
  assignedCodes: 0,
  printedBatches: 0,
  pendingPrintBatches: 0,
  lastBatchAt: null,
  recentBatches: [],
});

export const normalizeManufacturerRows = (rows: unknown[]): ManufacturerRow[] =>
  rows.flatMap((row) => {
    const value = asRecord(row);
    if (!value) return [];

    const id = String(value.id || "").trim();
    const email = String(value.email || "").trim();
    const name = String(value.name || "").trim();
    if (!id || !email || !name) return [];

    return [
      {
        id,
        name,
        email,
        isActive: typeof value.isActive === "boolean" ? value.isActive : true,
        createdAt: typeof value.createdAt === "string" ? value.createdAt : undefined,
        licenseeId: typeof value.licenseeId === "string" ? value.licenseeId : undefined,
        location: typeof value.location === "string" ? value.location : null,
        website: typeof value.website === "string" ? value.website : null,
      },
    ];
  });

export const normalizeBatchRows = (rows: unknown[]): BatchRow[] =>
  rows.flatMap((row) => {
    const value = asRecord(row);
    if (!value) return [];

    const manufacturer = asRecord(value.manufacturer);
    const id = String(value.id || "").trim();
    const name = String(value.name || "").trim();
    if (!id) return [];

    return [
      {
        id,
        name,
        licenseeId: typeof value.licenseeId === "string" ? value.licenseeId : undefined,
        manufacturerId:
          typeof value.manufacturerId === "string"
            ? value.manufacturerId
            : typeof manufacturer?.id === "string"
              ? manufacturer.id
              : null,
        totalCodes: Number(value.totalCodes || 0),
        availableCodes: Number(value.availableCodes || 0),
        printedAt: typeof value.printedAt === "string" ? value.printedAt : null,
        createdAt: typeof value.createdAt === "string" ? value.createdAt : undefined,
        startCode: typeof value.startCode === "string" ? value.startCode : undefined,
        endCode: typeof value.endCode === "string" ? value.endCode : undefined,
      },
    ];
  });

export const formatAssignmentTimestamp = (value?: string | null) => {
  if (!value) return "No assignments yet";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "No assignments yet";
  return format(parsed, "MMM d, yyyy HH:mm");
};

export const manufacturerOperationalStatus = (stats?: ManufacturerStats) => {
  if (!stats || stats.assignedBatches === 0) {
    return { label: "No active batches", tone: "secondary" as const };
  }

  if (stats.pendingPrintBatches > 0) {
    return { label: "Needs action", tone: "outline" as const };
  }

  if (stats.printedBatches > 0) {
    return { label: "Printing complete", tone: "default" as const };
  }

  return { label: "Ready to print", tone: "secondary" as const };
};
