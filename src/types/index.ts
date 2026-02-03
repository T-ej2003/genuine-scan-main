export type UserRole = "super_admin" | "licensee_admin" | "manufacturer";
export type QRStatus = "DORMANT" | "ACTIVE" | "ALLOCATED" | "PRINTED" | "SCANNED";

export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  licenseeId?: string;
  createdAt: string;
  isActive: boolean;
  deletedAt?: string | null;
  location?: string | null;
  website?: string | null;
}

export interface Licensee {
  id: string;
  name: string;
  prefix: string;
  description?: string | null;
  brandName?: string | null;
  location?: string | null;
  website?: string | null;
  supportEmail?: string | null;
  supportPhone?: string | null;
  isActive: boolean;
  createdAt: string;
  updatedAt?: string;
}

export interface QRRange {
  id: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  usedCodes: number;
  createdAt: string;
}

export interface Batch {
  id: string;
  name: string;
  licenseeId: string;
  manufacturerId?: string | null;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt?: string | null;
  createdAt: string;
  updatedAt: string;

  licensee?: { id: string; name: string; prefix: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  _count?: { qrCodes: number };
}

export interface ProductBatch {
  id: string;
  licenseeId: string;
  parentBatchId: string;

  productName: string;
  productCode: string;
  description?: string | null;

  serialStart: number;
  serialEnd: number;
  serialFormat: string;

  startCode: string;
  endCode: string;
  totalCodes: number;

  manufacturerId?: string | null;
  printedAt?: string | null;

  createdAt: string;
  updatedAt: string;

  licensee?: { id: string; name: string; prefix: string } | null;
  parentBatch?: { id: string; name: string; startCode: string; endCode: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  _count?: { qrCodes: number };
}

export interface QRCode {
  id: string;
  code: string;
  licenseeId: string;
  batchId?: string | null;
  productBatchId?: string | null;
  status: QRStatus;
  scannedAt?: string | null;
  scanCount: number;
  createdAt: string;
  updatedAt: string;

  batch?: { id: string; name: string; printedAt?: string | null } | null;
  productBatch?: { id: string; productName: string; productCode: string; printedAt?: string | null } | null;
}

export interface AuditLog {
  id: string;
  userId?: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  details?: any;
  ipAddress?: string | null;
  createdAt: string;
}
