import prisma from "../../config/database";
import { UserRole, UserStatus } from "@prisma/client";
import { hashPassword } from "./passwordService";
import { newCsrfToken } from "./tokenService";
import { hashToken, randomOpaqueToken } from "../../utils/security";
import { sendAuthEmail } from "./authEmailService";
import { createAuditLog } from "../auditService";

const addHours = (d: Date, hours: number) => new Date(d.getTime() + hours * 60 * 60 * 1000);

const inferOrgIdForLicensee = async (licenseeId: string) => {
  const licensee = await prisma.licensee.findUnique({
    where: { id: licenseeId },
    select: { id: true, orgId: true, name: true, isActive: true },
  });
  if (!licensee) throw new Error("Licensee not found");
  if (!licensee.orgId) throw new Error("Licensee has no organization configured");
  if (!licensee.isActive) throw new Error("Licensee is inactive");
  return { orgId: licensee.orgId, licenseeName: licensee.name };
};

const normalizeRole = (role: string): UserRole => {
  const r = String(role || "").trim().toUpperCase();
  if (r === "PLATFORM_SUPER_ADMIN") return UserRole.PLATFORM_SUPER_ADMIN;
  if (r === "ORG_ADMIN") return UserRole.ORG_ADMIN;
  if (r === "MANUFACTURER_ADMIN") return UserRole.MANUFACTURER_ADMIN;
  if (r === "MANUFACTURER_USER") return UserRole.MANUFACTURER_USER;

  // Legacy roles (accepted for backward compatibility).
  if (r === "SUPER_ADMIN") return UserRole.SUPER_ADMIN;
  if (r === "LICENSEE_ADMIN") return UserRole.LICENSEE_ADMIN;
  if (r === "MANUFACTURER") return UserRole.MANUFACTURER;

  throw new Error("Unsupported role");
};

const defaultNameForEmail = (email: string) => {
  const local = String(email.split("@")[0] || "").trim();
  if (!local) return "Invited user";
  return local.slice(0, 80);
};

const resolveWebAppBaseUrl = () => {
  const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
  if (cors) return cors.replace(/\/+$/, "");
  return "http://localhost:8080";
};

const PLATFORM_ORG_ID = "00000000-0000-0000-0000-000000000000";

const getOrCreatePlatformOrgId = async () => {
  const existing = await prisma.organization.findUnique({ where: { id: PLATFORM_ORG_ID }, select: { id: true } });
  if (existing) return existing.id;
  const created = await prisma.organization.create({
    data: {
      id: PLATFORM_ORG_ID,
      name: "Platform",
      isActive: true,
    },
    select: { id: true },
  });
  return created.id;
};

export const createInvite = async (input: {
  email: string;
  role: string;
  name?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  createdByUserId: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const email = String(input.email || "").trim().toLowerCase();
  if (!email) throw new Error("Email is required");

  const role = normalizeRole(input.role);

  const isPlatformRole = role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

  const licenseeId = input.licenseeId ? String(input.licenseeId).trim() : null;
  const manufacturerId = input.manufacturerId ? String(input.manufacturerId).trim() : null;

  const org = isPlatformRole
    ? { orgId: null as string | null, licenseeName: null as string | null }
    : licenseeId
      ? await inferOrgIdForLicensee(licenseeId)
      : (() => {
          throw new Error("licenseeId is required for org-scoped roles");
        })();

  const inviteOrgId = isPlatformRole ? await getOrCreatePlatformOrgId() : (org.orgId as string);

  const now = new Date();
  const expiresAt = addHours(now, 24);

  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  const userName = String(input.name || "").trim() || defaultNameForEmail(email);

  const result = await prisma.$transaction(async (tx) => {
    const existing = await tx.user.findUnique({ where: { email }, select: { id: true } });
    if (existing) throw new Error("User with this email already exists");

    const createdUser = await tx.user.create({
      data: {
        email,
        name: userName,
        role,
        orgId: org.orgId,
        licenseeId: isPlatformRole ? null : licenseeId,
        status: UserStatus.INVITED,
        isActive: true,
        passwordHash: null,
      },
      select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true, status: true },
    });

    const invite = await tx.invite.create({
      data: {
        orgId: inviteOrgId,
        licenseeId: isPlatformRole ? null : licenseeId,
        email,
        role,
        manufacturerId,
        tokenHash,
        expiresAt,
        createdByUserId: input.createdByUserId,
      },
      select: { id: true, email: true, role: true, expiresAt: true },
    });

    return { createdUser, invite };
  });

  // Send email outside the transaction (delivery should not block DB state).
  const baseUrl = resolveWebAppBaseUrl();
  const acceptUrl = `${baseUrl}/accept-invite?token=${encodeURIComponent(rawToken)}`;

  const subject = "You have been invited to AuthenticQR";
  const text =
    `You have been invited to AuthenticQR.\n\n` +
    `To set your password and activate your account, open this link (expires in 24 hours):\n` +
    `${acceptUrl}\n\n` +
    `If you were not expecting this email, you can ignore it.`;

  await sendAuthEmail({
    toAddress: email,
    subject,
    text,
    template: "invite",
    orgId: result.createdUser.orgId,
    licenseeId: result.createdUser.licenseeId,
    actorUserId: input.createdByUserId,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });

  await createAuditLog({
    userId: input.createdByUserId,
    licenseeId: result.createdUser.licenseeId || undefined,
    orgId: result.createdUser.orgId || undefined,
    action: "AUTH_INVITE_CREATED",
    entityType: "Invite",
    entityId: result.invite.id,
    details: { email, role: result.invite.role, expiresAt: result.invite.expiresAt, manufacturerId },
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  } as any);

  return {
    inviteId: result.invite.id,
    expiresAt: result.invite.expiresAt,
    email: result.invite.email,
    role: result.invite.role,
    csrfToken: newCsrfToken(),
  };
};

export const acceptInvite = async (input: {
  rawToken: string;
  password: string;
  name?: string | null;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const tokenHash = hashToken(input.rawToken);
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    const invite = await tx.invite.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        orgId: true,
        licenseeId: true,
        email: true,
        role: true,
        manufacturerId: true,
        expiresAt: true,
        usedAt: true,
      },
    });
    if (!invite) throw new Error("Invalid or expired invite token");
    if (invite.usedAt) throw new Error("Invite already used");
    if (invite.expiresAt.getTime() <= now.getTime()) throw new Error("Invite expired");

    const user = await tx.user.findUnique({
      where: { email: invite.email },
      select: { id: true, status: true, isActive: true, deletedAt: true },
    });
    if (!user) throw new Error("Invited user record not found");
    if (user.deletedAt || user.isActive === false) throw new Error("Account is disabled");

    const passwordHash = await hashPassword(input.password);
    const userName = String(input.name || "").trim();

    const updatedUser = await tx.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        status: UserStatus.ACTIVE,
        name: userName ? userName : undefined,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
      select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true, status: true },
    });

    await tx.invite.update({
      where: { id: invite.id },
      data: { usedAt: now, acceptedByUserId: user.id },
    });

    return { user: updatedUser, inviteId: invite.id };
  });

  await createAuditLog({
    userId: result.user.id,
    licenseeId: result.user.licenseeId || undefined,
    orgId: result.user.orgId || undefined,
    action: "AUTH_INVITE_ACCEPTED",
    entityType: "Invite",
    entityId: result.inviteId,
    details: {},
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  } as any);

  return result.user;
};
