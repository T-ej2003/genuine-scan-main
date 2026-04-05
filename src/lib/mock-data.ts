import type { AuditLog, Batch, Licensee, QRCode, QRStatus, User } from "@/types";

export type ManufacturerRecord = {
  id: string;
  name: string;
  licenseeId: string;
  location?: string | null;
  email: string;
  createdAt: string;
  isActive: boolean;
};

const MOCK_CREATED_AT = "2024-01-01T00:00:00Z";
const MOCK_UPDATED_AT = "2024-01-01T00:00:00Z";

export const mockUsers: User[] = [
  {
    id: "1",
    email: "admin@mscqr.com",
    name: "Super Admin",
    role: "super_admin",
    createdAt: MOCK_CREATED_AT,
    isActive: true,
  },
  {
    id: "2",
    email: "licensee@alphaproducts.com",
    name: "Alpha Products Admin",
    role: "licensee_admin",
    licenseeId: "lic-1",
    createdAt: "2024-01-15T00:00:00Z",
    isActive: true,
  },
  {
    id: "3",
    email: "manufacturer@betamfg.com",
    name: "Beta Manufacturing Admin",
    role: "manufacturer",
    licenseeId: "lic-1",
    createdAt: "2024-02-01T00:00:00Z",
    isActive: true,
  },
];

export const mockLicensees: Licensee[] = [
  {
    id: "lic-1",
    name: "Alpha Products Inc.",
    prefix: "A",
    location: "New York, USA",
    website: "https://alphaproducts.com",
    createdAt: "2024-01-15T00:00:00Z",
    updatedAt: "2024-01-15T00:00:00Z",
    isActive: true,
  },
  {
    id: "lic-2",
    name: "Beta Industries",
    prefix: "B",
    location: "London, UK",
    website: "https://betaindustries.co.uk",
    createdAt: "2024-02-01T00:00:00Z",
    updatedAt: "2024-02-01T00:00:00Z",
    isActive: true,
  },
  {
    id: "lic-3",
    name: "Gamma Solutions",
    prefix: "X1",
    location: "Tokyo, Japan",
    website: "https://gamma.jp",
    createdAt: "2024-03-01T00:00:00Z",
    updatedAt: "2024-03-01T00:00:00Z",
    isActive: false,
  },
];

export const mockManufacturers: ManufacturerRecord[] = [
  {
    id: "mfg-1",
    name: "Beta Manufacturing Co.",
    licenseeId: "lic-1",
    location: "Chicago, USA",
    email: "contact@betamfg.com",
    createdAt: "2024-02-01T00:00:00Z",
    isActive: true,
  },
  {
    id: "mfg-2",
    name: "Delta Printers",
    licenseeId: "lic-1",
    location: "Los Angeles, USA",
    email: "info@deltaprinters.com",
    createdAt: "2024-02-15T00:00:00Z",
    isActive: true,
  },
  {
    id: "mfg-3",
    name: "Epsilon Labels",
    licenseeId: "lic-2",
    location: "Manchester, UK",
    email: "hello@epsilonlabels.co.uk",
    createdAt: "2024-03-01T00:00:00Z",
    isActive: true,
  },
];

export const mockBatches: Batch[] = [
  {
    id: "batch-1",
    name: "Batch 001 - Spring Collection",
    licenseeId: "lic-1",
    manufacturerId: "mfg-1",
    startCode: "A0000000001",
    endCode: "A0000010000",
    totalCodes: 10000,
    createdAt: "2024-02-01T00:00:00Z",
    updatedAt: "2024-02-10T00:00:00Z",
    printedAt: "2024-02-10T00:00:00Z",
  },
  {
    id: "batch-2",
    name: "Batch 002 - Summer Line",
    licenseeId: "lic-1",
    manufacturerId: "mfg-2",
    startCode: "A0000010001",
    endCode: "A0000025000",
    totalCodes: 15000,
    createdAt: "2024-03-01T00:00:00Z",
    updatedAt: "2024-03-05T00:00:00Z",
  },
  {
    id: "batch-3",
    name: "Batch 003 - Reserved",
    licenseeId: "lic-1",
    startCode: "A0000025001",
    endCode: "A0000050000",
    totalCodes: 25000,
    createdAt: "2024-03-15T00:00:00Z",
    updatedAt: "2024-03-15T00:00:00Z",
  },
];

const mockQrStatusCycle: QRStatus[] = ["DORMANT", "ALLOCATED", "PRINTED", "SCANNED"];

export const generateMockQRCodes = (licensee: Licensee, count = 100): QRCode[] => {
  return Array.from({ length: count }, (_, index) => {
    const status = mockQrStatusCycle[index % mockQrStatusCycle.length];
    const sequence = index + 1;
    return {
      id: `qr-${licensee.id}-${sequence}`,
      code: `${licensee.prefix}${sequence.toString().padStart(10, "0")}`,
      licenseeId: licensee.id,
      status,
      createdAt: MOCK_CREATED_AT,
      updatedAt: MOCK_UPDATED_AT,
      scanCount: status === "SCANNED" ? (index % 5) + 1 : 0,
    };
  });
};

export const mockAuditLogs: AuditLog[] = [
  {
    id: "log-1",
    userId: "1",
    action: "CREATE_LICENSEE",
    entityType: "licensee",
    entityId: "lic-1",
    details: { summary: "Created licensee Alpha Products Inc." },
    createdAt: "2024-01-15T10:30:00Z",
  },
  {
    id: "log-2",
    userId: "2",
    action: "CREATE_BATCH",
    entityType: "batch",
    entityId: "batch-1",
    details: { summary: "Created Batch 001 - Spring Collection" },
    createdAt: "2024-02-01T14:20:00Z",
  },
  {
    id: "log-3",
    userId: "2",
    action: "ASSIGN_BATCH",
    entityType: "batch",
    entityId: "batch-1",
    details: { summary: "Assigned the batch to Beta Manufacturing Co." },
    createdAt: "2024-02-05T09:15:00Z",
  },
  {
    id: "log-4",
    userId: "3",
    action: "CONFIRM_PRINT",
    entityType: "batch",
    entityId: "batch-1",
    details: { summary: "Confirmed printing for Batch 001 - Spring Collection" },
    createdAt: "2024-02-10T16:45:00Z",
  },
];
