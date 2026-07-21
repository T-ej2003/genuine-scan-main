import { Prisma, UserRole, UserStatus } from "@prisma/client";

import type { CanonicalDbContext } from "../../../lib/canonicalDbContext";

type QueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const roles = new Set<string>(Object.values(UserRole));
const statuses = new Set<string>(Object.values(UserStatus));
const platformRoles = new Set<string>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);
const licenseeAdminRoles = new Set<string>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);
const manufacturerRoles = new Set<string>([UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER]);
const invitePurposes = new Set(["auth-invite-create", "licensee-admin-invite-resend"]);
const HASH_PATTERN = /^(?:[a-f0-9]{12}:)?[a-f0-9]{64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const canonicalRoleFamily = (role: UserRole) => {
  if (licenseeAdminRoles.has(role)) return UserRole.LICENSEE_ADMIN;
  if (manufacturerRoles.has(role)) return UserRole.MANUFACTURER;
  return role;
};

const required = (value: unknown, field: string, maximum = 320) => {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized || normalized.length > maximum) {
    throw new Error(`app_rls.prepare_invitation returned an invalid ${field}`);
  }
  return normalized;
};

const optional = (value: unknown, field: string, maximum = 320) =>
  value == null ? null : required(value, field, maximum);

const normalizedEmail = (value: unknown, field: string, nullable = false) => {
  if (nullable && value == null) return null;
  const email = required(value, field).toLowerCase();
  if (email !== value || !EMAIL_PATTERN.test(email)) {
    throw new Error(`app_rls.prepare_invitation returned an invalid ${field}`);
  }
  return email;
};

const timestamp = (value: unknown, field: string, nullable = false) => {
  if (nullable && value == null) return null;
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`app_rls.prepare_invitation returned an invalid ${field}`);
  }
  return value;
};

const projection = [
  "actorDisplayName",
  "actorEmail",
  "actorUserId",
  "inviteEmail",
  "inviteExpiresAt",
  "inviteId",
  "inviteRole",
  "licenseeName",
  "linkAction",
  "userEmail",
  "userId",
  "userLicenseeId",
  "userName",
  "userOrganizationId",
  "userRole",
  "userStatus",
  "workspaceOrganizationId",
] as const;

export type PreparedInvitation = {
  actorDisplayName: string;
  actorEmail: string;
  actorUserId: string;
  inviteEmail: string;
  inviteExpiresAt: Date | null;
  inviteId: string | null;
  inviteRole: UserRole;
  licenseeName: string | null;
  linkAction: "LINKED_EXISTING" | "ALREADY_LINKED" | null;
  userEmail: string;
  userId: string;
  userLicenseeId: string | null;
  userName: string;
  userOrganizationId: string | null;
  userRole: UserRole;
  userStatus: UserStatus;
  workspaceOrganizationId: string | null;
};

const validateAuthority = (
  context: CanonicalDbContext,
  input: {
    requestedRole: UserRole;
    requestedLicenseeId: string | null;
    allowExistingInvitedUser: boolean;
    requireExistingUser: boolean;
  }
) => {
  if (!invitePurposes.has(context.purpose)) throw new Error("INVITE_PURPOSE_DENIED");
  if (!platformRoles.has(context.role) && !licenseeAdminRoles.has(context.role)) {
    throw new Error("INVITE_ROLE_DENIED");
  }
  if (context.authAssurance !== "mfa-verified" && context.authAssurance !== "step-up-verified") {
    throw new Error("INVITE_ASSURANCE_DENIED");
  }

  if (context.purpose === "licensee-admin-invite-resend") {
    if (
      !platformRoles.has(context.role) ||
      !input.requireExistingUser ||
      !input.allowExistingInvitedUser ||
      !input.requestedLicenseeId ||
      !licenseeAdminRoles.has(input.requestedRole)
    ) {
      throw new Error("INVITE_RESEND_AUTHORITY_DENIED");
    }
    return;
  }

  if (licenseeAdminRoles.has(context.role)) {
    if (
      !context.licenseeId ||
      input.requestedLicenseeId !== context.licenseeId ||
      platformRoles.has(input.requestedRole)
    ) {
      throw new Error("INVITE_SCOPE_DENIED");
    }
  }
};

export const prepareInvitation = async (
  db: QueryClient,
  context: CanonicalDbContext,
  input: {
    requestedEmail: string | null;
    requestedName: string;
    requestedRole: UserRole;
    requestedLicenseeId: string | null;
    requestedManufacturerId: string | null;
    allowExistingInvitedUser: boolean;
    requireExistingUser: boolean;
    tokenHash: string;
    createdAt: Date;
    expiresAt: Date;
    actorSessionId: string;
    ipHash: string | null;
    userAgent: string | null;
  }
): Promise<PreparedInvitation> => {
  validateAuthority(context, input);
  const requestedEmail = normalizedEmail(input.requestedEmail, "requested email", input.requireExistingUser);
  if (!input.requireExistingUser && !requestedEmail) throw new Error("INVITE_EMAIL_REQUIRED");
  const requestedName = required(input.requestedName, "requested name", 120);
  if (!roles.has(input.requestedRole)) throw new Error("INVITE_ROLE_INVALID");
  const requestedLicenseeId = optional(input.requestedLicenseeId, "requested licensee ID", 64);
  const requestedManufacturerId = optional(input.requestedManufacturerId, "requested manufacturer ID", 64);
  if (platformRoles.has(input.requestedRole)) {
    if (requestedLicenseeId || requestedManufacturerId) throw new Error("INVITE_SCOPE_INVALID");
  } else if (!requestedLicenseeId) {
    throw new Error("INVITE_LICENSEE_REQUIRED");
  }
  if (requestedManufacturerId && (!manufacturerRoles.has(input.requestedRole) || !input.allowExistingInvitedUser)) {
    throw new Error("INVITE_MANUFACTURER_INVALID");
  }
  if (!HASH_PATTERN.test(input.tokenHash)) throw new Error("INVITE_TOKEN_HASH_INVALID");
  const createdAt = timestamp(input.createdAt, "created-at timestamp")!;
  const expiresAt = timestamp(input.expiresAt, "expiry timestamp")!;
  const lifetime = expiresAt.getTime() - createdAt.getTime();
  if (lifetime <= 0 || lifetime > 24 * 60 * 60 * 1000) throw new Error("INVITE_EXPIRY_INVALID");
  const actorSessionId = required(input.actorSessionId, "actor session ID", 191);
  const ipHash = input.ipHash == null ? null : String(input.ipHash).trim().toLowerCase();
  if (ipHash && !HASH_PATTERN.test(ipHash)) throw new Error("INVITE_IP_HASH_INVALID");
  const userAgent = input.userAgent == null ? null : String(input.userAgent).trim();
  if (userAgent && (userAgent.length > 512 || /[\u0000-\u001f\u007f]/.test(userAgent))) {
    throw new Error("INVITE_USER_AGENT_INVALID");
  }

  const rows = await db.$queryRaw<PreparedInvitation[]>`
    SELECT * FROM app_rls.prepare_invitation(
      ${context.userId},
      ${actorSessionId},
      ${context.requestId},
      ${context.purpose},
      ${requestedEmail},
      ${requestedName},
      ${input.requestedRole}::text,
      ${requestedLicenseeId},
      ${requestedManufacturerId},
      ${input.allowExistingInvitedUser},
      ${input.requireExistingUser},
      ${input.tokenHash},
      ${createdAt}::timestamp without time zone,
      ${expiresAt}::timestamp without time zone,
      ${ipHash},
      ${userAgent}
    )
  `;
  if (rows.length !== 1) throw new Error("app_rls.prepare_invitation returned an invalid row count");
  const row = rows[0];
  const actual = Object.keys(row).sort();
  if (actual.length !== projection.length || actual.some((key, index) => key !== projection[index])) {
    throw new Error("app_rls.prepare_invitation returned an unexpected projection");
  }

  row.actorUserId = required(row.actorUserId, "actor user ID", 64);
  row.actorEmail = normalizedEmail(row.actorEmail, "actor email")!;
  row.actorDisplayName = required(row.actorDisplayName, "actor display name", 320);
  row.inviteId = optional(row.inviteId, "invite ID", 64);
  row.inviteEmail = normalizedEmail(row.inviteEmail, "invite email")!;
  row.inviteRole = required(row.inviteRole, "invite role", 64) as UserRole;
  row.inviteExpiresAt = timestamp(row.inviteExpiresAt, "invite expiry", true);
  row.licenseeName = optional(row.licenseeName, "licensee name", 200);
  row.linkAction = optional(row.linkAction, "link action", 32) as PreparedInvitation["linkAction"];
  row.userId = required(row.userId, "user ID", 64);
  row.userEmail = normalizedEmail(row.userEmail, "user email")!;
  row.userName = required(row.userName, "user name", 120);
  row.userRole = required(row.userRole, "user role", 64) as UserRole;
  row.userLicenseeId = optional(row.userLicenseeId, "user licensee ID", 64);
  row.userOrganizationId = optional(row.userOrganizationId, "user organization ID", 64);
  row.userStatus = required(row.userStatus, "user status", 32) as UserStatus;
  row.workspaceOrganizationId = optional(row.workspaceOrganizationId, "workspace organization ID", 64);

  if (row.actorUserId !== context.userId) throw new Error("app_rls.prepare_invitation returned a foreign actor");
  if (!roles.has(row.inviteRole) || !roles.has(row.userRole) || !statuses.has(row.userStatus)) {
    throw new Error("app_rls.prepare_invitation returned an unsupported account state");
  }
  if (row.inviteRole !== input.requestedRole || (requestedEmail && row.inviteEmail !== requestedEmail)) {
    throw new Error("app_rls.prepare_invitation returned a foreign invitation");
  }
  if (canonicalRoleFamily(row.userRole) !== canonicalRoleFamily(input.requestedRole)) {
    throw new Error("app_rls.prepare_invitation returned a foreign role family");
  }
  if (requestedManufacturerId && row.userId !== requestedManufacturerId) {
    throw new Error("app_rls.prepare_invitation returned a foreign manufacturer");
  }
  if (row.inviteEmail !== row.userEmail) throw new Error("app_rls.prepare_invitation returned a foreign user");
  if (row.inviteId ? !row.inviteExpiresAt : row.inviteExpiresAt || !row.linkAction) {
    throw new Error("app_rls.prepare_invitation returned an inconsistent invitation state");
  }
  if (row.inviteId && (row.inviteExpiresAt!.getTime() !== expiresAt.getTime() || row.userStatus !== UserStatus.INVITED)) {
    throw new Error("app_rls.prepare_invitation returned an inconsistent invitation lifecycle");
  }
  if (row.linkAction && row.userStatus !== UserStatus.ACTIVE) {
    throw new Error("app_rls.prepare_invitation returned an inactive linked account");
  }
  if (row.linkAction && row.linkAction !== "LINKED_EXISTING" && row.linkAction !== "ALREADY_LINKED") {
    throw new Error("app_rls.prepare_invitation returned an unsupported link action");
  }
  return row;
};
