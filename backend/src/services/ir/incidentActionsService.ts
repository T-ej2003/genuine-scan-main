import {
  IncidentActorType,
  IncidentEventType,
  UserRole,
  UserStatus,
} from "@prisma/client";
import prisma from "../../config/database";
import { createAuditLog } from "../auditService";
import { recordIncidentEvent } from "../incidentService";

export type IrContainmentAction =
  | "FLAG_QR_UNDER_INVESTIGATION"
  | "UNFLAG_QR_UNDER_INVESTIGATION"
  | "SUSPEND_BATCH"
  | "REINSTATE_BATCH"
  | "SUSPEND_ORG"
  | "REINSTATE_ORG"
  | "SUSPEND_MANUFACTURER_USERS"
  | "REINSTATE_MANUFACTURER_USERS";

const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role: UserRole) => MANUFACTURER_ROLES.includes(role);

export const applyContainmentAction = async (input: {
  incidentId: string;
  actorUserId: string;
  action: IrContainmentAction;
  reason: string;
  qrCodeId?: string | null;
  batchId?: string | null;
  licenseeId?: string | null;
  manufacturerUserIds?: string[];
  ipAddress?: string | null;
}) => {
  const now = new Date();

  const incident = await prisma.incident.findUnique({
    where: { id: input.incidentId },
    select: {
      id: true,
      licenseeId: true,
      qrCodeId: true,
      qrCodeValue: true,
      qrCode: {
        select: {
          id: true,
          batchId: true,
          batch: { select: { id: true, manufacturerId: true, licenseeId: true } },
        },
      },
      scanEvent: {
        select: {
          id: true,
          batchId: true,
          batch: { select: { id: true, manufacturerId: true, licenseeId: true } },
        },
      },
    },
  });
  if (!incident) throw new Error("INCIDENT_NOT_FOUND");

  const resolvedQrId =
    input.qrCodeId ||
    incident.qrCodeId ||
    incident.qrCode?.id ||
    null;
  const resolvedBatchId =
    input.batchId ||
    incident.qrCode?.batchId ||
    incident.scanEvent?.batchId ||
    incident.qrCode?.batch?.id ||
    incident.scanEvent?.batch?.id ||
    null;
  const resolvedLicenseeId =
    input.licenseeId ||
    incident.licenseeId ||
    incident.qrCode?.batch?.licenseeId ||
    incident.scanEvent?.batch?.licenseeId ||
    null;

  const resolvedManufacturerId =
    incident.qrCode?.batch?.manufacturerId ||
    incident.scanEvent?.batch?.manufacturerId ||
    null;

  const actionDetails: any = {
    action: input.action,
    reason: input.reason,
    qrCodeId: resolvedQrId,
    batchId: resolvedBatchId,
    licenseeId: resolvedLicenseeId,
    manufacturerId: resolvedManufacturerId,
    performedAt: now.toISOString(),
  };

  if (input.action === "FLAG_QR_UNDER_INVESTIGATION") {
    if (!resolvedQrId) throw new Error("MISSING_QR");
    await prisma.qRCode.update({
      where: { id: resolvedQrId },
      data: {
        underInvestigationAt: now,
        underInvestigationReason: input.reason,
      },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId || undefined,
      action: "IR_FLAG_QR_UNDER_INVESTIGATION",
      entityType: "QRCode",
      entityId: resolvedQrId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "UNFLAG_QR_UNDER_INVESTIGATION") {
    if (!resolvedQrId) throw new Error("MISSING_QR");
    await prisma.qRCode.update({
      where: { id: resolvedQrId },
      data: {
        underInvestigationAt: null,
        underInvestigationReason: null,
      },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId || undefined,
      action: "IR_UNFLAG_QR_UNDER_INVESTIGATION",
      entityType: "QRCode",
      entityId: resolvedQrId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "SUSPEND_BATCH") {
    if (!resolvedBatchId) throw new Error("MISSING_BATCH");
    await prisma.batch.update({
      where: { id: resolvedBatchId },
      data: { suspendedAt: now, suspendedReason: input.reason },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId || undefined,
      action: "IR_SUSPEND_BATCH",
      entityType: "Batch",
      entityId: resolvedBatchId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "REINSTATE_BATCH") {
    if (!resolvedBatchId) throw new Error("MISSING_BATCH");
    await prisma.batch.update({
      where: { id: resolvedBatchId },
      data: { suspendedAt: null, suspendedReason: null },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId || undefined,
      action: "IR_REINSTATE_BATCH",
      entityType: "Batch",
      entityId: resolvedBatchId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "SUSPEND_ORG") {
    if (!resolvedLicenseeId) throw new Error("MISSING_LICENSEE");
    await prisma.licensee.update({
      where: { id: resolvedLicenseeId },
      data: { suspendedAt: now, suspendedReason: input.reason },
    });

    // Revoke refresh tokens for all users in this tenant.
    await prisma.refreshToken.updateMany({
      where: {
        user: { licenseeId: resolvedLicenseeId },
        revokedAt: null,
      },
      data: { revokedAt: now, revokedReason: `Licensee suspended by incident ${incident.id}` },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId,
      action: "IR_SUSPEND_ORG",
      entityType: "Licensee",
      entityId: resolvedLicenseeId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "REINSTATE_ORG") {
    if (!resolvedLicenseeId) throw new Error("MISSING_LICENSEE");
    await prisma.licensee.update({
      where: { id: resolvedLicenseeId },
      data: { suspendedAt: null, suspendedReason: null },
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: resolvedLicenseeId,
      action: "IR_REINSTATE_ORG",
      entityType: "Licensee",
      entityId: resolvedLicenseeId,
      details: { incidentId: incident.id, reason: input.reason },
      ipAddress: input.ipAddress || undefined,
    });
  }

  if (input.action === "SUSPEND_MANUFACTURER_USERS" || input.action === "REINSTATE_MANUFACTURER_USERS") {
    const userIds = Array.from(
      new Set(
        (input.manufacturerUserIds && input.manufacturerUserIds.length > 0
          ? input.manufacturerUserIds
          : resolvedManufacturerId
          ? [resolvedManufacturerId]
          : []
        )
          .map((v) => String(v || "").trim())
          .filter(Boolean)
      )
    );
    if (userIds.length === 0) throw new Error("MISSING_MANUFACTURER_USERS");

    const users = await prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, role: true, licenseeId: true },
    });
    const invalid = users.filter((u) => !isManufacturerRole(u.role));
    if (invalid.length > 0) throw new Error("TARGET_NOT_MANUFACTURER");

    if (input.action === "SUSPEND_MANUFACTURER_USERS") {
      await prisma.user.updateMany({
        where: { id: { in: userIds } },
        data: {
          status: UserStatus.DISABLED,
          isActive: false,
          disabledAt: now,
          disabledReason: input.reason,
        },
      });

      await prisma.refreshToken.updateMany({
        where: { userId: { in: userIds }, revokedAt: null },
        data: { revokedAt: now, revokedReason: `User suspended by incident ${incident.id}` },
      });

      await createAuditLog({
        userId: input.actorUserId,
        licenseeId: resolvedLicenseeId || undefined,
        action: "IR_SUSPEND_MANUFACTURER_USERS",
        entityType: "User",
        entityId: userIds[0],
        details: { incidentId: incident.id, reason: input.reason, userIds },
        ipAddress: input.ipAddress || undefined,
      });
    } else {
      await prisma.user.updateMany({
        where: { id: { in: userIds } },
        data: {
          status: UserStatus.ACTIVE,
          isActive: true,
          disabledAt: null,
          disabledReason: null,
          lockedUntil: null,
          failedLoginAttempts: 0,
        },
      });

      await createAuditLog({
        userId: input.actorUserId,
        licenseeId: resolvedLicenseeId || undefined,
        action: "IR_REINSTATE_MANUFACTURER_USERS",
        entityType: "User",
        entityId: userIds[0],
        details: { incidentId: incident.id, reason: input.reason, userIds },
        ipAddress: input.ipAddress || undefined,
      });
    }

    actionDetails.manufacturerUserIds = userIds;
  }

  await recordIncidentEvent({
    incidentId: incident.id,
    actorType: IncidentActorType.ADMIN,
    actorUserId: input.actorUserId,
    eventType: IncidentEventType.UPDATED_FIELDS,
    eventPayload: actionDetails,
  });

  return {
    ok: true,
    incidentId: incident.id,
    details: actionDetails,
  };
};

