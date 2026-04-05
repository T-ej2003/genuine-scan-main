export type LicenseeRow = {
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
  _count?: { users: number; qrCodes: number; batches: number };
  latestRange?: {
    startCode: string;
    endCode: string;
    totalCodes: number;
    createdAt: string;
  } | null;
  adminOnboarding?: {
    state?: "PENDING" | "ACTIVE" | "UNASSIGNED";
    adminUser?: {
      id: string;
      name: string;
      email: string;
      role: string;
      status?: string;
      isActive?: boolean;
      createdAt?: string;
    } | null;
    pendingInvite?: {
      id: string;
      email: string;
      expiresAt?: string;
      createdAt?: string;
    } | null;
  } | null;
};

export type CreateLicenseeForm = {
  name: string;
  prefix: string;
  description: string;
  isActive: boolean;
  brandName: string;
  location: string;
  website: string;
  supportEmail: string;
  supportPhone: string;
  adminName: string;
  adminEmail: string;
  rangeStart: string;
  rangeEnd: string;
  createManufacturerNow: boolean;
  manufacturerName: string;
  manufacturerEmail: string;
};

export type EditLicenseeForm = {
  id: string;
  name: string;
  description: string;
  isActive: boolean;
  brandName: string;
  location: string;
  website: string;
  supportEmail: string;
  supportPhone: string;
};

export type CreateUserForm = {
  licenseeId: string;
  name: string;
  email: string;
  role: "LICENSEE_ADMIN" | "MANUFACTURER";
};

export type AllocateRangeForm = {
  licenseeId: string;
  mode: "quantity" | "range";
  startNumber: string;
  endNumber: string;
  quantity: string;
  receivedBatchName: string;
  lastStartCode: string | null;
  lastEndCode: string | null;
  lastEndNumber: number | null;
  suggestedNextStart: number;
};
