import {
  CustomerTrustLevel,
  CustomerTrustReviewState,
  CustomerVerificationAuthState,
  CustomerVerificationEntryMethod,
  IncidentActorType,
  IncidentEventType,
  IncidentHandoffStage,
  IncidentPriority,
  IncidentSeverity,
  IncidentStatus,
  OwnershipTransferStatus,
  Prisma,
  SupportTicketStatus,
  UserRole,
  VerificationDecisionOutcome,
  VerificationDegradationMode,
  VerificationProofTier,
  VerificationReplacementStatus,
  VerificationRiskBand,
} from "@prisma/client";

export type B02Db = Prisma.TransactionClient;

type RequestAccessStatus = "NEW" | "REVIEWING" | "CONTACTED" | "QUALIFIED" | "CLOSED";
type SupportIssueStatus = "OPEN" | "RESPONDED" | "CLOSED";
type ChallengePurpose = "ENROLLMENT" | "LOGIN" | "STEP_UP";

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B02 repository requires ${label}`);
  return normalized;
};

const page = (value: number, label: string, maximum: number) => {
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new Error(`B02 repository received invalid ${label}`);
  }
  return value;
};

const requestAccessSelect = {
  id: true,
  referenceCode: true,
  fullName: true,
  companyName: true,
  roleTitle: true,
  country: true,
  monthlyGarmentVolume: true,
  message: true,
  sourcePage: true,
  referrer: true,
  status: true,
  assignedToUserId: true,
  reviewedByUserId: true,
  reviewedAt: true,
  createdAt: true,
  updatedAt: true,
  assignedToUser: { select: { id: true, name: true } },
  reviewedByUser: { select: { id: true, name: true } },
} satisfies Prisma.RequestAccessSelect;

export const listRequestAccessRows = (
  tx: B02Db,
  input: { status?: RequestAccessStatus; limit: number; offset: number }
) => {
  const where = input.status ? { status: input.status } : {};
  const take = page(input.limit, "request-access limit", 100);
  if (take === 0) throw new Error("B02 repository requires a positive request-access limit");
  const skip = page(input.offset, "request-access offset", 2_000);
  return Promise.all([
    tx.requestAccess.findMany({
      where,
      orderBy: [{ createdAt: "desc" }],
      take,
      skip,
      select: requestAccessSelect,
    }),
    tx.requestAccess.count({ where }),
  ]);
};

export const updateRequestAccessRow = async (
  tx: B02Db,
  input: {
    id: string;
    actorUserId: string;
    status?: RequestAccessStatus;
    internalNote?: string | null;
    assignedToUserId?: string | null;
  }
) => {
  const id = required(input.id, "a request-access ID");
  const actorUserId = required(input.actorUserId, "an actor user ID");
  const existing = await tx.requestAccess.findUnique({
    where: { id },
    select: { id: true, status: true, assignedToUserId: true },
  });
  if (!existing) return null;
  const statusChanged = Boolean(input.status && input.status !== existing.status);
  return tx.requestAccess.update({
    where: { id },
    data: {
      ...(input.status ? { status: input.status } : {}),
      ...(input.internalNote !== undefined ? { internalNote: input.internalNote } : {}),
      ...(input.assignedToUserId !== undefined ? { assignedToUserId: input.assignedToUserId } : {}),
      ...(statusChanged ? { reviewedAt: new Date(), reviewedByUserId: actorUserId } : {}),
    },
    select: requestAccessSelect,
  });
};

const supportIssueSelect = {
  id: true,
  reporterUserId: true,
  reporterRole: true,
  licenseeId: true,
  referenceCode: true,
  publicName: true,
  issueType: true,
  verificationCode: true,
  productReference: true,
  priority: true,
  title: true,
  description: true,
  status: true,
  responseMessage: true,
  respondedAt: true,
  respondedByUserId: true,
  sourcePath: true,
  pageUrl: true,
  autoDetected: true,
  createdAt: true,
  updatedAt: true,
  reporterUser: { select: { id: true, name: true, role: true } },
  respondedByUser: { select: { id: true, name: true, role: true } },
  licensee: { select: { id: true, name: true, prefix: true } },
} satisfies Prisma.SupportIssueReportSelect;

const supportTicketSelect = {
  id: true,
  incidentId: true,
  referenceCode: true,
  licenseeId: true,
  customerEmail: true,
  subject: true,
  status: true,
  priority: true,
  assignedToUserId: true,
  slaDueAt: true,
  firstResponseAt: true,
  resolvedAt: true,
  createdAt: true,
  updatedAt: true,
  incident: {
    select: {
      id: true,
      qrCodeValue: true,
      status: true,
      severity: true,
      slaDueAt: true,
      handoff: { select: { currentStage: true, slaDueAt: true } },
    },
  },
  assignedToUser: { select: { id: true, name: true } },
} satisfies Prisma.SupportTicketSelect;

export const createSupportIssueRow = (
  tx: B02Db,
  input: {
    reporterUserId: string;
    reporterRole: UserRole;
    licenseeId?: string | null;
    title: string;
    description?: string | null;
    sourcePath?: string | null;
    pageUrl?: string | null;
    autoDetected: boolean;
    screenshotPath?: string | null;
    screenshotMime?: string | null;
    screenshotSize?: number | null;
    diagnostics?: Prisma.InputJsonValue | null;
  }
) => tx.supportIssueReport.create({
  data: {
    reporterUserId: required(input.reporterUserId, "a support reporter user ID"),
    reporterRole: input.reporterRole,
    licenseeId: input.licenseeId || null,
    title: required(input.title, "a support title"),
    description: input.description || null,
    sourcePath: input.sourcePath || null,
    pageUrl: input.pageUrl || null,
    autoDetected: input.autoDetected,
    screenshotPath: input.screenshotPath || null,
    screenshotMime: input.screenshotMime || null,
    screenshotSize: input.screenshotSize ?? null,
    diagnostics: input.diagnostics ?? Prisma.JsonNull,
  },
  select: supportIssueSelect,
});

const requireActiveSupportLicensee = async (tx: B02Db, licenseeId: string) => {
  const id = required(licenseeId, "an explicit support licensee selector");
  const active = await tx.licensee.findFirst({
    where: {
      id,
      isActive: true,
      suspendedAt: null,
      organization: { is: { isActive: true } },
    },
    select: { id: true },
  });
  if (!active) throw new Error("B02 support licensee selector is inactive or foreign");
  return active.id;
};

export const listSupportTicketRows = async (
  tx: B02Db,
  input: {
    licenseeId: string;
    status?: SupportTicketStatus;
    priority?: IncidentPriority;
    search?: string | null;
    limit: number;
    offset: number;
  }
) => {
  const licenseeId = await requireActiveSupportLicensee(tx, input.licenseeId);
  const search = String(input.search || "").trim();
  const where: Prisma.SupportTicketWhereInput = {
    licenseeId,
    ...(input.status ? { status: input.status } : {}),
    ...(input.priority ? { priority: input.priority } : {}),
    ...(search
      ? {
          OR: [
            { referenceCode: { contains: search, mode: "insensitive" as const } },
            { subject: { contains: search, mode: "insensitive" as const } },
            { incident: { is: { qrCodeValue: { contains: search.toUpperCase(), mode: "insensitive" as const } } } },
          ],
        }
      : {}),
  };
  const take = page(input.limit, "support-ticket limit", 200);
  if (take === 0) throw new Error("B02 repository requires a positive support-ticket limit");
  const skip = page(input.offset, "support-ticket offset", 2_000);
  return Promise.all([
    tx.supportTicket.findMany({
      where,
      orderBy: [{ createdAt: "desc" }],
      take,
      skip,
      select: supportTicketSelect,
    }),
    tx.supportTicket.count({ where }),
  ]);
};

export const loadSupportTicketRow = async (
  tx: B02Db,
  input: { id: string; licenseeId: string }
) => {
  const licenseeId = await requireActiveSupportLicensee(tx, input.licenseeId);
  return tx.supportTicket.findFirst({
    where: { id: required(input.id, "a support-ticket ID"), licenseeId },
    select: {
      ...supportTicketSelect,
      incident: {
        select: {
          id: true,
          qrCodeValue: true,
          status: true,
          severity: true,
          slaDueAt: true,
          handoff: true,
        },
      },
      messages: {
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          actorType: true,
          actorUserId: true,
          message: true,
          isInternal: true,
          createdAt: true,
          actorUser: { select: { id: true, name: true } },
        },
      },
    },
  });
};

export const updateSupportTicketRow = async (
  tx: B02Db,
  input: {
    id: string;
    licenseeId: string;
    expectedUpdatedAt: Date;
    status?: SupportTicketStatus;
    assignedToUserId?: string | null;
    changedAt: Date;
  }
) => {
  const id = required(input.id, "a support-ticket ID");
  const licenseeId = await requireActiveSupportLicensee(tx, input.licenseeId);
  const terminal = input.status === SupportTicketStatus.RESOLVED || input.status === SupportTicketStatus.CLOSED;
  const changed = await tx.supportTicket.updateMany({
    where: { id, licenseeId, updatedAt: input.expectedUpdatedAt },
    data: {
      ...(input.status
        ? {
            status: input.status,
            resolvedAt: terminal ? input.changedAt : null,
          }
        : {}),
      ...(input.assignedToUserId !== undefined ? { assignedToUserId: input.assignedToUserId } : {}),
    },
  });
  if (changed.count !== 1) return null;
  return tx.supportTicket.findFirst({ where: { id, licenseeId }, select: supportTicketSelect });
};

export const createSupportTicketMessageRow = async (
  tx: B02Db,
  input: {
    ticketId: string;
    licenseeId: string;
    actorType: IncidentActorType;
    actorUserId: string;
    message: string;
    isInternal: boolean;
  }
) => {
  const ticketId = required(input.ticketId, "a support-ticket ID");
  const licenseeId = await requireActiveSupportLicensee(tx, input.licenseeId);
  const ticket = await tx.supportTicket.findFirst({ where: { id: ticketId, licenseeId }, select: { id: true } });
  if (!ticket) return null;
  return tx.supportTicketMessage.create({
    data: {
      ticketId,
      actorType: input.actorType,
      actorUserId: required(input.actorUserId, "a support-message actor user ID"),
      message: required(input.message, "a support message").slice(0, 4_000),
      isInternal: input.isInternal,
    },
    select: {
      id: true,
      ticketId: true,
      actorType: true,
      actorUserId: true,
      message: true,
      isInternal: true,
      createdAt: true,
    },
  });
};

export const listSupportIssueRows = async (
  tx: B02Db,
  input: { licenseeId: string; platform: boolean; limit: number; offset: number }
) => {
  const licenseeId = await requireActiveSupportLicensee(tx, input.licenseeId);
  const where = { licenseeId };
  const take = page(input.limit, "support-report limit", 200);
  if (take === 0) throw new Error("B02 repository requires a positive support-report limit");
  const skip = page(input.offset, "support-report offset", 5_000);
  return Promise.all([
    tx.supportIssueReport.findMany({
      where,
      orderBy: [{ createdAt: "desc" }],
      take,
      skip,
      select: supportIssueSelect,
    }),
    tx.supportIssueReport.count({ where }),
  ]);
};

export const loadSupportIssueForResponse = (
  tx: B02Db,
  input: { id: string; licenseeId: string; platform: boolean }
) => requireActiveSupportLicensee(tx, input.licenseeId).then((licenseeId) =>
  tx.supportIssueReport.findFirst({
    where: { id: required(input.id, "a support-report ID"), licenseeId },
    select: {
      ...supportIssueSelect,
      publicEmail: true,
      reporterUser: { select: { id: true, name: true, email: true, licenseeId: true, orgId: true } },
    },
  })
);

export const updateSupportIssueResponse = (
  tx: B02Db,
  input: {
    id: string;
    licenseeId: string;
    actorUserId: string;
    status: SupportIssueStatus;
    message: string;
    respondedAt: Date;
    emailDeliveryStatus?: string | null;
    emailErrorCode?: string | null;
  }
) => tx.supportIssueReport.update({
  where: {
    id: required(input.id, "a support-report ID"),
    licenseeId: required(input.licenseeId, "a support licensee ID"),
  },
  data: {
    status: input.status,
    responseMessage: required(input.message, "a support response"),
    respondedAt: input.respondedAt,
    respondedByUserId: required(input.actorUserId, "a support responder user ID"),
    ...(input.emailDeliveryStatus ? { emailDeliveryStatus: input.emailDeliveryStatus } : {}),
    ...(input.emailErrorCode !== undefined ? { emailErrorCode: input.emailErrorCode } : {}),
  },
  select: supportIssueSelect,
});

export const authorizeSupportScreenshot = (
  tx: B02Db,
  input: { fileName: string; actorUserId: string; licenseeId: string; platform: boolean }
) => requireActiveSupportLicensee(tx, input.licenseeId).then((licenseeId) =>
  tx.supportIssueReport.findFirst({
    where: {
      screenshotPath: required(input.fileName, "a screenshot file name"),
      licenseeId,
      ...(input.platform ? {} : { reporterUserId: required(input.actorUserId, "an actor user ID") }),
    },
    select: { reporterUserId: true, licenseeId: true, screenshotMime: true },
  })
);

const customerTrustSelect = {
  id: true,
  qrCodeId: true,
  customerUserId: true,
  trustLevel: true,
  reviewState: true,
  source: true,
  reviewNote: true,
  reviewedByUserId: true,
  reviewedAt: true,
  revokedAt: true,
  revokedReason: true,
  lastAssertionAt: true,
  lastVerifiedAt: true,
  claimedAt: true,
  linkedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.CustomerTrustCredentialSelect;

export const findCustomerTrustCredential = (
  tx: B02Db,
  input: {
    qrCodeId: string;
    customerUserId: string;
    deviceTokenHash?: string | null;
  }
) => {
  const qrCodeId = required(input.qrCodeId, "a QR code ID");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const deviceTokenHash = String(input.deviceTokenHash || "").trim();
  return tx.customerTrustCredential.findFirst({
    where: {
      qrCodeId,
      OR: [{ customerUserId }, ...(deviceTokenHash ? [{ deviceTokenHash }] : [])],
    },
    orderBy: [{ updatedAt: "desc" }],
    select: { ...customerTrustSelect, deviceTokenHash: true, customerEmail: true, metadata: true },
  });
};

type TrustWrite = {
  customerUserId: string;
  customerEmail?: string | null;
  deviceTokenHash?: string | null;
  trustLevel: CustomerTrustLevel;
  reviewState: CustomerTrustReviewState;
  source: string;
  reviewNote?: string | null;
  reviewedByUserId?: string | null;
  reviewedAt?: Date | null;
  revokedAt?: Date | null;
  revokedReason?: string | null;
  lastAssertionAt?: Date | null;
  lastVerifiedAt?: Date | null;
  claimedAt?: Date | null;
  linkedAt?: Date | null;
  metadata?: Prisma.InputJsonValue | null;
};

const trustWriteData = (input: TrustWrite) => ({
  customerUserId: required(input.customerUserId, "a customer user ID"),
  customerEmail: input.customerEmail || null,
  deviceTokenHash: input.deviceTokenHash || null,
  trustLevel: input.trustLevel,
  reviewState: input.reviewState,
  source: required(input.source, "a trust source"),
  reviewNote: input.reviewNote || null,
  reviewedByUserId: input.reviewedByUserId || null,
  reviewedAt: input.reviewedAt || null,
  revokedAt: input.revokedAt || null,
  revokedReason: input.revokedReason || null,
  lastAssertionAt: input.lastAssertionAt || null,
  lastVerifiedAt: input.lastVerifiedAt || null,
  claimedAt: input.claimedAt || null,
  linkedAt: input.linkedAt || null,
  metadata: input.metadata ?? Prisma.JsonNull,
});

export const createCustomerTrustCredential = (
  tx: B02Db,
  input: TrustWrite & { qrCodeId: string }
) => tx.customerTrustCredential.create({
  data: { qrCodeId: required(input.qrCodeId, "a QR code ID"), ...trustWriteData(input) },
  select: customerTrustSelect,
});

export const updateCustomerTrustCredential = (
  tx: B02Db,
  input: TrustWrite & { id: string }
) => tx.customerTrustCredential.update({
  where: {
    id: required(input.id, "a trust credential ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
  },
  data: trustWriteData(input),
  select: customerTrustSelect,
});

const requireScopedQr = async (tx: B02Db, qrCodeId: string, licenseeId: string) => {
  const id = required(qrCodeId, "a QR code ID");
  const qr = await tx.qRCode.findFirst({
    where: { id, licenseeId: required(licenseeId, "a licensee ID") },
    select: { id: true },
  });
  if (!qr) throw new Error("B02 QR scope is stale or foreign");
  return qr.id;
};

export const listCustomerTrustCredentials = async (
  tx: B02Db,
  input: { qrCodeId: string; licenseeId: string }
) => {
  const qrCodeId = await requireScopedQr(tx, input.qrCodeId, input.licenseeId);
  return tx.customerTrustCredential.findMany({
    where: { qrCodeId },
    orderBy: [{ updatedAt: "desc" }],
    select: customerTrustSelect,
  });
};

export const getCustomerTrustCredential = async (
  tx: B02Db,
  input: { id: string; qrCodeId: string; licenseeId: string }
) => {
  const qrCodeId = await requireScopedQr(tx, input.qrCodeId, input.licenseeId);
  return tx.customerTrustCredential.findFirst({
    where: { id: required(input.id, "a trust credential ID"), qrCodeId },
    select: customerTrustSelect,
  });
};

const ownershipSelect = {
  id: true,
  qrCodeId: true,
  userId: true,
  deviceTokenHash: true,
  ipHash: true,
  userAgentHash: true,
  claimSource: true,
  linkedAt: true,
  claimedAt: true,
} satisfies Prisma.OwnershipSelect;

const ownershipTransferSelect = {
  id: true,
  qrCodeId: true,
  ownershipId: true,
  initiatedByCustomerId: true,
  initiatedByEmail: true,
  recipientEmail: true,
  status: true,
  expiresAt: true,
  acceptedAt: true,
  cancelledAt: true,
  lastViewedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.OwnershipTransferSelect;

const ownershipQrSelect = {
  id: true,
  code: true,
  status: true,
  licenseeId: true,
  printJobId: true,
  printJob: {
    select: {
      status: true,
      pipelineState: true,
      confirmedAt: true,
      printSession: { select: { status: true, completedAt: true } },
    },
  },
} satisfies Prisma.QRCodeSelect;

const ownershipQrIdentifier = (input: { code?: string; id?: string }) => {
  const code = String(input.code || "").trim();
  const id = String(input.id || "").trim();
  if (Boolean(code) === Boolean(id)) throw new Error("B02 ownership QR lookup requires exactly one identifier");
  return code ? { code } : { id };
};

export const loadClaimableCustomerQr = (
  tx: B02Db,
  input: { code: string; customerUserId: string }
) => {
  required(input.customerUserId, "a customer user ID");
  return tx.qRCode.findFirst({
    where: { ...ownershipQrIdentifier(input), ownership: { is: null } },
    select: ownershipQrSelect,
  });
};

export const loadOwnedCustomerQr = (
  tx: B02Db,
  input: { code?: string; id?: string; customerUserId: string; deviceTokenHash?: string | null }
) => {
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const deviceTokenHash = String(input.deviceTokenHash || "").trim();
  return tx.qRCode.findFirst({
    where: {
      ...ownershipQrIdentifier(input),
      ownership: {
        is: {
          OR: [{ userId: customerUserId }, ...(deviceTokenHash ? [{ userId: null, deviceTokenHash }] : [])],
        },
      },
    },
    select: ownershipQrSelect,
  });
};

export const loadTransferRecipientQr = async (
  tx: B02Db,
  input: { id: string; transferId: string; customerUserId: string; checkedAt: Date }
) => {
  const id = required(input.id, "a QR code ID");
  const transfer = await tx.ownershipTransfer.findFirst({
    where: {
      id: required(input.transferId, "an ownership-transfer ID"),
      qrCodeId: id,
      initiatedByCustomerId: { not: required(input.customerUserId, "a customer user ID") },
      status: OwnershipTransferStatus.PENDING,
      expiresAt: { gt: input.checkedAt },
    },
    select: { id: true },
  });
  if (!transfer) return null;
  return tx.qRCode.findFirst({ where: { id }, select: ownershipQrSelect });
};

export const loadBoundOwnershipByQrCodeId = (
  tx: B02Db,
  input: { qrCodeId: string; customerUserId: string; deviceTokenHash?: string | null }
) => {
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const deviceTokenHash = String(input.deviceTokenHash || "").trim();
  return tx.ownership.findFirst({
    where: {
      qrCodeId: required(input.qrCodeId, "a QR code ID"),
      OR: [
        { userId: customerUserId },
        ...(deviceTokenHash ? [{ userId: null, deviceTokenHash }] : []),
      ],
    },
    select: ownershipSelect,
  });
};

export const claimOwnershipForCustomer = (
  tx: B02Db,
  input: {
    qrCodeId: string;
    customerUserId: string;
    deviceTokenHash?: string | null;
    ipHash?: string | null;
    userAgentHash?: string | null;
  }
) => tx.ownership.create({
  data: {
    qrCodeId: required(input.qrCodeId, "a QR code ID"),
    userId: required(input.customerUserId, "a customer user ID"),
    deviceTokenHash: input.deviceTokenHash || null,
    ipHash: input.ipHash || null,
    userAgentHash: input.userAgentHash || null,
    claimSource: "USER",
  },
  select: ownershipSelect,
});

export const linkDeviceOwnershipToCustomer = async (
  tx: B02Db,
  input: {
    qrCodeId: string;
    customerUserId: string;
    deviceTokenHash: string;
    linkedAt: Date;
  }
) => {
  const qrCodeId = required(input.qrCodeId, "a QR code ID");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const changed = await tx.ownership.updateMany({
    where: {
      qrCodeId,
      userId: null,
      deviceTokenHash: required(input.deviceTokenHash, "a device-claim digest"),
    },
    data: { userId: customerUserId, linkedAt: input.linkedAt, claimSource: "DEVICE_AND_USER" },
  });
  if (changed.count !== 1) return null;
  return tx.ownership.findFirst({ where: { qrCodeId, userId: customerUserId }, select: ownershipSelect });
};

export const expirePendingOwnershipTransfers = (
  tx: B02Db,
  input: { customerUserId: string; qrCodeId?: string | null; checkedAt: Date }
) => tx.ownershipTransfer.updateMany({
  where: {
    initiatedByCustomerId: required(input.customerUserId, "a customer user ID"),
    ...(input.qrCodeId ? { qrCodeId: required(input.qrCodeId, "a QR code ID") } : {}),
    status: OwnershipTransferStatus.PENDING,
    expiresAt: { lt: input.checkedAt },
  },
  data: { status: OwnershipTransferStatus.EXPIRED },
});

export const loadPendingOwnershipTransferForOwner = (
  tx: B02Db,
  input: { qrCodeId: string; customerUserId: string; transferId?: string | null }
) => tx.ownershipTransfer.findFirst({
  where: {
    qrCodeId: required(input.qrCodeId, "a QR code ID"),
    initiatedByCustomerId: required(input.customerUserId, "a customer user ID"),
    status: OwnershipTransferStatus.PENDING,
    ...(input.transferId ? { id: required(input.transferId, "an ownership-transfer ID") } : {}),
  },
  orderBy: [{ createdAt: "desc" }, { id: "desc" }],
  select: ownershipTransferSelect,
});

export const loadOwnershipTransferByProof = async (
  tx: B02Db,
  input: {
    tokenHashCandidates: string[];
    customerUserId: string;
    customerEmail: string;
    checkedAt: Date;
  }
) => {
  const tokenHashCandidates = uniqueIds(input.tokenHashCandidates, "an ownership-transfer token digest");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const customerEmail = required(input.customerEmail, "a customer email").toLowerCase();
  const where: Prisma.OwnershipTransferWhereInput = {
    tokenHash: { in: tokenHashCandidates },
    initiatedByCustomerId: { not: customerUserId },
    status: OwnershipTransferStatus.PENDING,
    expiresAt: { gt: input.checkedAt },
    OR: [{ recipientEmail: null }, { recipientEmail: { equals: customerEmail, mode: "insensitive" } }],
  };
  const transfer = await tx.ownershipTransfer.findFirst({ where, select: { id: true } });
  if (!transfer) return null;
  await tx.ownershipTransfer.updateMany({
    where: { id: transfer.id, ...where },
    data: { lastViewedAt: input.checkedAt },
  });
  return tx.ownershipTransfer.findFirst({ where: { id: transfer.id, ...where }, select: ownershipTransferSelect });
};

export const createOwnershipTransferRow = async (
  tx: B02Db,
  input: {
    qrCodeId: string;
    customerUserId: string;
    customerEmail: string;
    recipientEmail?: string | null;
    tokenHash: string;
    expiresAt: Date;
    createdAt: Date;
    metadata?: Prisma.InputJsonValue | null;
  }
) => {
  const qrCodeId = required(input.qrCodeId, "a QR code ID");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const ownership = await tx.ownership.findFirst({
    where: { qrCodeId, userId: customerUserId },
    select: { id: true },
  });
  if (!ownership) return null;
  await tx.ownershipTransfer.updateMany({
    where: { qrCodeId, initiatedByCustomerId: customerUserId, status: OwnershipTransferStatus.PENDING },
    data: { status: OwnershipTransferStatus.CANCELLED, cancelledAt: input.createdAt },
  });
  return tx.ownershipTransfer.create({
    data: {
      qrCodeId,
      ownershipId: ownership.id,
      initiatedByCustomerId: customerUserId,
      initiatedByEmail: required(input.customerEmail, "a customer email").toLowerCase(),
      recipientEmail: input.recipientEmail ? input.recipientEmail.trim().toLowerCase() : null,
      tokenHash: required(input.tokenHash, "an ownership-transfer token digest"),
      status: OwnershipTransferStatus.PENDING,
      expiresAt: input.expiresAt,
      metadata: input.metadata ?? Prisma.JsonNull,
    },
    select: ownershipTransferSelect,
  });
};

export const acceptOwnershipTransferRow = async (
  tx: B02Db,
  input: {
    transferId: string;
    ownershipId: string;
    qrCodeId: string;
    customerUserId: string;
    claimedAt: Date;
    ipHash?: string | null;
    userAgentHash?: string | null;
  }
) => {
  const transferId = required(input.transferId, "an ownership-transfer ID");
  const qrCodeId = required(input.qrCodeId, "a QR code ID");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const accepted = await tx.ownershipTransfer.updateMany({
    where: {
      id: transferId,
      qrCodeId,
      ownershipId: required(input.ownershipId, "an ownership ID"),
      initiatedByCustomerId: { not: customerUserId },
      status: OwnershipTransferStatus.PENDING,
      expiresAt: { gt: input.claimedAt },
    },
    data: { status: OwnershipTransferStatus.ACCEPTED, acceptedAt: input.claimedAt },
  });
  if (accepted.count !== 1) return null;
  const ownership = await tx.ownership.update({
    where: { id: input.ownershipId, qrCodeId },
    data: {
      userId: customerUserId,
      linkedAt: input.claimedAt,
      claimedAt: input.claimedAt,
      ipHash: input.ipHash || null,
      userAgentHash: input.userAgentHash || null,
      claimSource: "USER_TRANSFERRED",
    },
    select: ownershipSelect,
  });
  await tx.ownershipTransfer.updateMany({
    where: { qrCodeId, status: OwnershipTransferStatus.PENDING, id: { not: transferId } },
    data: { status: OwnershipTransferStatus.CANCELLED, cancelledAt: input.claimedAt },
  });
  const transfer = await tx.ownershipTransfer.findUnique({ where: { id: transferId }, select: ownershipTransferSelect });
  return transfer ? { ownership, transfer } : null;
};

export const cancelOwnershipTransferRow = async (
  tx: B02Db,
  input: { id: string; qrCodeId: string; customerUserId: string; cancelledAt: Date }
) => {
  const id = required(input.id, "an ownership-transfer ID");
  const where = {
    id,
    qrCodeId: required(input.qrCodeId, "a QR code ID"),
    initiatedByCustomerId: required(input.customerUserId, "a customer user ID"),
    status: OwnershipTransferStatus.PENDING,
  };
  const changed = await tx.ownershipTransfer.updateMany({
    where,
    data: { status: OwnershipTransferStatus.CANCELLED, cancelledAt: input.cancelledAt },
  });
  if (changed.count !== 1) return null;
  return tx.ownershipTransfer.findFirst({ where: { id }, select: ownershipTransferSelect });
};

const customerSessionSelect = {
  id: true,
  verificationDecisionId: true,
  qrCodeId: true,
  code: true,
  entryMethod: true,
  authState: true,
  customerUserId: true,
  intakeCompletedAt: true,
  revealedAt: true,
  expiresAt: true,
  proofBindingIssuedAt: true,
  proofBindingExpiresAt: true,
  proofBindingReplayEpoch: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.CustomerVerificationSessionSelect;

export const getCustomerVerificationSessionRow = (
  tx: B02Db,
  input: { id: string; customerUserId: string; includeIntake?: boolean }
) => tx.customerVerificationSession.findFirst({
  where: {
    id: required(input.id, "a customer verification session ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
  },
  select: {
    ...customerSessionSelect,
    proofBindingTokenHash: true,
    metadata: true,
    ...(input.includeIntake ? { trustIntake: true } : {}),
  },
});

export const markCustomerVerificationIntakeCompleted = (
  tx: B02Db,
  input: { id: string; customerUserId: string; intakeCompletedAt: Date }
) => tx.customerVerificationSession.updateMany({
  where: {
    id: required(input.id, "a customer verification session ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
    intakeCompletedAt: null,
  },
  data: {
    authState: CustomerVerificationAuthState.VERIFIED,
    intakeCompletedAt: input.intakeCompletedAt,
  },
});

export const revealCustomerVerificationSessionRow = (
  tx: B02Db,
  input: { id: string; customerUserId: string; revealedAt: Date }
) => tx.customerVerificationSession.updateMany({
  where: {
    id: required(input.id, "a customer verification session ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
    intakeCompletedAt: { not: null },
    revealedAt: null,
  },
  data: {
    authState: CustomerVerificationAuthState.VERIFIED,
    revealedAt: input.revealedAt,
  },
});

export const upsertCustomerTrustIntakeRow = async (
  tx: B02Db,
  input: {
    sessionId: string;
    customerUserId: string;
    customerEmail?: string | null;
    purchaseChannel: string;
    sourceCategory?: string | null;
    platformName?: string | null;
    sellerName?: string | null;
    listingUrl?: string | null;
    orderReference?: string | null;
    storeName?: string | null;
    purchaseCity?: string | null;
    purchaseCountry?: string | null;
    purchaseDate?: Date | null;
    packagingState?: string | null;
    packagingConcern?: string | null;
    scanReason: string;
    ownershipIntent: string;
    notes?: string | null;
    answers?: Prisma.InputJsonValue | null;
  }
) => {
  const sessionId = required(input.sessionId, "a customer verification session ID");
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const session = await tx.customerVerificationSession.findFirst({
    where: { id: sessionId, customerUserId, revealedAt: null },
    select: { id: true },
  });
  if (!session) throw new Error("B02 verification session is stale, foreign, or already revealed");
  const mutable = {
    purchaseChannel: required(input.purchaseChannel, "a purchase channel"),
    sourceCategory: input.sourceCategory || null,
    platformName: input.platformName || null,
    sellerName: input.sellerName || null,
    listingUrl: input.listingUrl || null,
    orderReference: input.orderReference || null,
    storeName: input.storeName || null,
    purchaseCity: input.purchaseCity || null,
    purchaseCountry: input.purchaseCountry || null,
    purchaseDate: input.purchaseDate || null,
    packagingState: input.packagingState || null,
    packagingConcern: input.packagingConcern || null,
    scanReason: required(input.scanReason, "a scan reason"),
    ownershipIntent: required(input.ownershipIntent, "an ownership intent"),
    notes: input.notes || null,
    answers: input.answers ?? Prisma.JsonNull,
  };
  return tx.customerTrustIntake.upsert({
    where: { sessionId },
    create: {
      sessionId,
      customerUserId,
      customerEmail: input.customerEmail || null,
      ...mutable,
    },
    update: mutable,
  });
};

const publicCredentialSelect = {
  id: true,
  customerUserId: true,
  label: true,
  counter: true,
  transports: true,
  lastUsedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.CustomerWebAuthnCredentialSelect;

export const listCustomerWebAuthnCredentialRows = (tx: B02Db, customerUserId: string) =>
  tx.customerWebAuthnCredential.findMany({
    where: { customerUserId: required(customerUserId, "a customer user ID") },
    orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
    select: { ...publicCredentialSelect, credentialId: true },
  });

export const createCustomerWebAuthnChallengeRow = (
  tx: B02Db,
  input: {
    customerUserId: string;
    customerEmail?: string | null;
    purpose: ChallengePurpose;
    ticketHash: string;
    challengeHash: string;
    credentialIds: string[];
    createdIpHash?: string | null;
    createdUserAgentHash?: string | null;
    origin?: string | null;
    rpId?: string | null;
    expiresAt: Date;
  }
) => tx.customerWebAuthnChallenge.create({
  data: {
    customerUserId: required(input.customerUserId, "a customer user ID"),
    customerEmail: input.customerEmail || null,
    purpose: input.purpose,
    ticketHash: required(input.ticketHash, "a WebAuthn ticket digest"),
    challengeHash: required(input.challengeHash, "a WebAuthn challenge digest"),
    credentialIds: input.credentialIds.map((id) => required(id, "a WebAuthn credential ID")),
    createdIpHash: input.createdIpHash || null,
    createdUserAgentHash: input.createdUserAgentHash || null,
    origin: input.origin || null,
    rpId: input.rpId || null,
    expiresAt: input.expiresAt,
  },
  select: { id: true, customerUserId: true, purpose: true, expiresAt: true, createdAt: true, origin: true, rpId: true },
});

export const loadCustomerWebAuthnChallengeRow = (
  tx: B02Db,
  input: { ticketHashCandidates: string[]; customerUserId: string; purpose?: ChallengePurpose; now: Date }
) => tx.customerWebAuthnChallenge.findFirst({
  where: {
    ticketHash: { in: input.ticketHashCandidates.map((value) => required(value, "a WebAuthn ticket digest")) },
    customerUserId: required(input.customerUserId, "a customer user ID"),
    ...(input.purpose ? { purpose: input.purpose } : {}),
    consumedAt: null,
    expiresAt: { gt: input.now },
  },
  orderBy: [{ createdAt: "desc" }],
  select: {
    id: true,
    customerUserId: true,
    customerEmail: true,
    purpose: true,
    challengeHash: true,
    expiresAt: true,
    consumedAt: true,
    credentialIds: true,
    origin: true,
    rpId: true,
  },
});

export const consumeCustomerWebAuthnChallengeRow = (
  tx: B02Db,
  input: { id: string; consumedAt: Date }
) => tx.customerWebAuthnChallenge.updateMany({
  where: { id: required(input.id, "a WebAuthn challenge ID"), consumedAt: null, expiresAt: { gt: input.consumedAt } },
  data: { consumedAt: input.consumedAt },
});

export const upsertCustomerWebAuthnCredentialRow = (
  tx: B02Db,
  input: {
    customerUserId: string;
    customerEmail?: string | null;
    label: string;
    credentialId: string;
    publicKeySpki: string;
    publicKeyAlgorithm: number;
    counter: number;
    transports: string[];
    lastUsedAt: Date;
  }
) => {
  const customerUserId = required(input.customerUserId, "a customer user ID");
  const credentialId = required(input.credentialId, "a WebAuthn credential ID");
  const mutable = {
    customerUserId,
    label: required(input.label, "a WebAuthn credential label"),
    publicKeySpki: required(input.publicKeySpki, "a WebAuthn public key"),
    publicKeyAlgorithm: input.publicKeyAlgorithm,
    counter: input.counter,
    transports: input.transports.map((value) => required(value, "a WebAuthn transport")),
    lastUsedAt: input.lastUsedAt,
  };
  return tx.customerWebAuthnCredential.findUnique({
    where: { credentialId },
    select: { customerUserId: true },
  }).then((existing) => {
    if (existing && existing.customerUserId !== customerUserId) {
      throw new Error("B02 WebAuthn credential belongs to a different customer");
    }
    return tx.customerWebAuthnCredential.upsert({
      where: { credentialId },
      update: mutable,
      create: { ...mutable, customerEmail: input.customerEmail || null, credentialId },
      select: { id: true, customerUserId: true, credentialId: true, counter: true, updatedAt: true },
    });
  });
};

export const loadCustomerWebAuthnCredentialRow = (
  tx: B02Db,
  input: { customerUserId: string; credentialId: string }
) => tx.customerWebAuthnCredential.findFirst({
  where: {
    customerUserId: required(input.customerUserId, "a customer user ID"),
    credentialId: required(input.credentialId, "a WebAuthn credential ID"),
  },
  select: {
    id: true,
    customerUserId: true,
    customerEmail: true,
    credentialId: true,
    publicKeySpki: true,
    counter: true,
  },
});

export const advanceCustomerWebAuthnCounter = (
  tx: B02Db,
  input: { id: string; customerUserId: string; expectedCounter: number; nextCounter: number; lastUsedAt: Date }
) => tx.customerWebAuthnCredential.updateMany({
  where: {
    id: required(input.id, "a WebAuthn credential row ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
    counter: input.expectedCounter,
  },
  data: { counter: input.nextCounter, lastUsedAt: input.lastUsedAt },
});

export const deleteCustomerWebAuthnCredentialRow = (
  tx: B02Db,
  input: { id: string; customerUserId: string }
) => tx.customerWebAuthnCredential.deleteMany({
  where: {
    id: required(input.id, "a WebAuthn credential row ID"),
    customerUserId: required(input.customerUserId, "a customer user ID"),
  },
});

export const loadIncidentForSupportArtifacts = (
  tx: B02Db,
  input: { incidentId: string; licenseeId: string }
) => {
  const incidentId = required(input.incidentId, "an incident ID");
  return tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`b02-support-workflow:${incidentId}`}, 0))`
    .then(() => tx.incident.findUnique({
    where: {
      id: incidentId,
      licenseeId: required(input.licenseeId, "a licensee ID"),
    },
    select: {
      id: true,
      licenseeId: true,
      qrCodeValue: true,
      description: true,
      customerEmail: true,
      priority: true,
      severity: true,
      status: true,
      slaDueAt: true,
      createdAt: true,
      handoff: {
        select: {
          id: true,
          currentStage: true,
          intakeAt: true,
          reviewAt: true,
          containmentAt: true,
          documentationAt: true,
          resolutionAt: true,
          completedAt: true,
          slaDueAt: true,
          updatedAt: true,
        },
      },
      supportTicket: {
        select: {
          id: true,
          referenceCode: true,
          status: true,
          firstResponseAt: true,
          resolvedAt: true,
          updatedAt: true,
        },
      },
    },
  }));
};

export const upsertIncidentHandoffRow = (
  tx: B02Db,
  input: {
    incidentId: string;
    currentStage: IncidentHandoffStage;
    intakeAt: Date;
    reviewAt?: Date | null;
    containmentAt?: Date | null;
    documentationAt?: Date | null;
    resolutionAt?: Date | null;
    completedAt?: Date | null;
    slaDueAt: Date;
  }
) => {
  const incidentId = required(input.incidentId, "an incident ID");
  const mutable = {
    currentStage: input.currentStage,
    reviewAt: input.reviewAt || null,
    containmentAt: input.containmentAt || null,
    documentationAt: input.documentationAt || null,
    resolutionAt: input.resolutionAt || null,
    completedAt: input.completedAt || null,
    slaDueAt: input.slaDueAt,
  };
  return tx.incidentHandoff.upsert({
    where: { incidentId },
    create: { incidentId, intakeAt: input.intakeAt, ...mutable },
    update: mutable,
    select: {
      id: true,
      incidentId: true,
      currentStage: true,
      intakeAt: true,
      reviewAt: true,
      containmentAt: true,
      documentationAt: true,
      resolutionAt: true,
      completedAt: true,
      slaDueAt: true,
    },
  });
};

export const upsertIncidentSupportTicketRow = (
  tx: B02Db,
  input: {
    incidentId: string;
    referenceCode: string;
    licenseeId: string;
    customerEmail?: string | null;
    subject: string;
    status: SupportTicketStatus;
    priority: IncidentPriority;
    slaDueAt: Date;
    firstResponseAt?: Date | null;
    resolvedAt?: Date | null;
  }
) => {
  const incidentId = required(input.incidentId, "an incident ID");
  const mutable = {
    licenseeId: required(input.licenseeId, "a licensee ID"),
    customerEmail: input.customerEmail || null,
    status: input.status,
    priority: input.priority,
    slaDueAt: input.slaDueAt,
    firstResponseAt: input.firstResponseAt || null,
    resolvedAt: input.resolvedAt || null,
  };
  return tx.supportTicket.upsert({
    where: { incidentId },
    create: {
      incidentId,
      referenceCode: required(input.referenceCode, "a support reference"),
      subject: required(input.subject, "a support subject"),
      ...mutable,
    },
    update: mutable,
    select: supportTicketSelect,
  });
};

export const createInitialSupportTicketMessageRow = (
  tx: B02Db,
  input: { ticketId: string; actorUserId?: string | null; incidentId: string }
) => tx.supportTicketMessage.create({
  data: {
    ticketId: required(input.ticketId, "a support-ticket ID"),
    actorType: IncidentActorType.SYSTEM,
    actorUserId: input.actorUserId || null,
    message: `Ticket created from incident ${required(input.incidentId, "an incident ID")}. Intake started.`,
    isInternal: true,
  },
  select: { id: true, ticketId: true, createdAt: true },
});

export const recordIncidentWorkflowEventRow = (
  tx: B02Db,
  input: {
    incidentId: string;
    actorType: IncidentActorType;
    actorUserId?: string | null;
    eventType: IncidentEventType;
    eventPayload?: Prisma.InputJsonValue | null;
  }
) => tx.incidentEvent.create({
  data: {
    incidentId: required(input.incidentId, "an incident ID"),
    actorType: input.actorType,
    actorUserId: input.actorUserId || null,
    eventType: input.eventType,
    eventPayload: input.eventPayload ?? Prisma.JsonNull,
  },
  select: { id: true, incidentId: true, eventType: true, createdAt: true },
});

const verificationDecisionSelect = {
  id: true,
  decisionVersion: true,
  qrCodeId: true,
  code: true,
  licenseeId: true,
  batchId: true,
  proofSource: true,
  proofTier: true,
  outcome: true,
  classification: true,
  reasonCodes: true,
  riskBand: true,
  replacementStatus: true,
  degradationMode: true,
  customerTrustLevel: true,
  isAuthentic: true,
  scanCount: true,
  riskScore: true,
  createdAt: true,
} satisfies Prisma.VerificationDecisionSelect;

const uniqueIds = (values: string[], label: string) =>
  Array.from(new Set(values.map((value) => required(value, label))));

const requireScopedQrIds = async (tx: B02Db, qrCodeIds: string[], licenseeId: string) => {
  const ids = uniqueIds(qrCodeIds, "a QR code ID");
  const rows = await tx.qRCode.findMany({
    where: { id: { in: ids }, licenseeId: required(licenseeId, "a licensee ID") },
    select: { id: true },
  });
  if (rows.length !== ids.length) throw new Error("B02 QR set contains stale or foreign scope");
  return ids;
};

export const listVerificationDecisionsByQrCodeIds = async (
  tx: B02Db,
  input: { qrCodeIds: string[]; licenseeId: string }
) => {
  const qrCodeIds = await requireScopedQrIds(tx, input.qrCodeIds, input.licenseeId);
  return tx.verificationDecision.findMany({
    where: { qrCodeId: { in: qrCodeIds }, licenseeId: input.licenseeId },
    orderBy: [{ qrCodeId: "asc" }, { createdAt: "desc" }],
    select: verificationDecisionSelect,
  });
};

export const listVerificationDecisionsByBatchIds = async (
  tx: B02Db,
  input: { batchIds: string[]; licenseeId: string }
) => {
  const batchIds = uniqueIds(input.batchIds, "a batch ID");
  const licenseeId = required(input.licenseeId, "a licensee ID");
  const batches = await tx.batch.findMany({
    where: { id: { in: batchIds }, licenseeId },
    select: { id: true },
  });
  if (batches.length !== batchIds.length) throw new Error("B02 batch set contains stale or foreign scope");
  return tx.verificationDecision.findMany({
    where: { batchId: { in: batchIds }, licenseeId },
    orderBy: [{ batchId: "asc" }, { createdAt: "desc" }],
    select: verificationDecisionSelect,
  });
};

export const listVerificationEvidenceRows = (
  tx: B02Db,
  input: { decisionIds: string[]; licenseeId: string }
) =>
  tx.verificationEvidenceSnapshot.findMany({
    where: {
      verificationDecisionId: { in: uniqueIds(input.decisionIds, "a verification decision ID") },
      verificationDecision: { is: { licenseeId: required(input.licenseeId, "a licensee ID") } },
    },
    orderBy: [{ createdAt: "desc" }],
    select: {
      id: true,
      verificationDecisionId: true,
      scanSummary: true,
      ownershipSnapshot: true,
      riskSignals: true,
      policySnapshot: true,
      lifecycleSnapshot: true,
      createdAt: true,
    },
  });

export const listVerificationTrustRows = async (
  tx: B02Db,
  input: { qrCodeIds: string[]; licenseeId: string }
) => {
  const qrCodeIds = await requireScopedQrIds(tx, input.qrCodeIds, input.licenseeId);
  return tx.customerTrustCredential.findMany({
    where: { qrCodeId: { in: qrCodeIds } },
    orderBy: [{ updatedAt: "desc" }],
    select: customerTrustSelect,
  });
};

export const loadVerificationEvidenceRow = (
  tx: B02Db,
  input: { decisionId: string; licenseeId: string }
) =>
  tx.verificationEvidenceSnapshot.findFirst({
    where: {
      verificationDecisionId: required(input.decisionId, "a verification decision ID"),
      verificationDecision: { is: { licenseeId: required(input.licenseeId, "a licensee ID") } },
    },
    orderBy: [{ createdAt: "desc" }],
    select: {
      id: true,
      verificationDecisionId: true,
      metadata: true,
      createdAt: true,
    },
  });

export const replaceVerificationEvidenceMetadata = (
  tx: B02Db,
  input: { id: string; decisionId: string; licenseeId: string; metadata: Prisma.InputJsonValue }
) => tx.verificationEvidenceSnapshot.findFirst({
  where: {
    id: required(input.id, "a verification evidence ID"),
    verificationDecisionId: required(input.decisionId, "a verification decision ID"),
    verificationDecision: { is: { licenseeId: required(input.licenseeId, "a licensee ID") } },
  },
  select: { id: true },
}).then((evidence) => evidence
  ? tx.verificationEvidenceSnapshot.update({
      where: { id: evidence.id },
      data: { metadata: input.metadata },
      select: { id: true, verificationDecisionId: true, createdAt: true },
    })
  : null);
