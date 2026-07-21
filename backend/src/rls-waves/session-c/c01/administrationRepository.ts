import { Prisma, UserRole } from "@prisma/client";

import {
  CanonicalDbContext,
  installCanonicalDbContext,
} from "../../../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../../../types";
import { getAdminStepUpWindowMinutes } from "../../../services/auth/authService";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);
const tenantAdminRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);

export const administrationPurposes = {
  createLicensee: "administration-create-licensee",
  updateLicensee: "administration-update-licensee",
  deleteLicensee: "administration-delete-licensee",
  createUser: "administration-create-user",
  updateUser: "administration-update-user",
  deleteUser: "administration-delete-user",
  restoreManufacturer: "administration-restore-manufacturer",
  upsertManufacturerLicenseeLink: "administration-upsert-manufacturer-licensee-link",
} as const;

export type AdministrationPurpose = (typeof administrationPurposes)[keyof typeof administrationPurposes];

export class AdministrationAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
    this.name = "AdministrationAccessError";
  }
}

const isUuid = (value: unknown): value is string => uuidPattern.test(String(value || "").trim());

const requiresPlatformActor = new Set<AdministrationPurpose>([
  administrationPurposes.createLicensee,
  administrationPurposes.updateLicensee,
  administrationPurposes.deleteLicensee,
]);

export const buildAdministrationBoundary = (
  user: AuthenticatedSessionClaims,
  input: {
    purpose: AdministrationPurpose;
    requestId: string;
    targetLicenseeId?: string | null;
    targetOrganizationId?: string | null;
  }
) => {
  const userId = String(user?.userId || "").trim();
  const requestId = String(input.requestId || "").trim();
  if (!isUuid(userId) || !isUuid(requestId) || user?.sessionStage !== "ACTIVE") {
    throw new AdministrationAccessError("Authenticated administration context is invalid", 401);
  }

  const platformActor = platformRoles.has(user.role);
  const tenantActor = tenantAdminRoles.has(user.role);
  if (!platformActor && !tenantActor) {
    throw new AdministrationAccessError("Administration actor is not authorized");
  }
  if (requiresPlatformActor.has(input.purpose) && !platformActor) {
    throw new AdministrationAccessError("Platform administration authority is required");
  }

  const mfaVerifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  if (
    user.authAssurance !== "ADMIN_MFA" ||
    !Number.isFinite(mfaVerifiedAt) ||
    Date.now() - mfaVerifiedAt > getAdminStepUpWindowMinutes() * 60_000
  ) {
    throw new AdministrationAccessError("Fresh administrator MFA is required", 428);
  }

  const claimedLicenseeId = String(user.licenseeId || "").trim();
  const claimedOrganizationId = String(user.orgId || "").trim();
  const targetLicenseeId = String(input.targetLicenseeId || "").trim();
  const targetOrganizationId = String(input.targetOrganizationId || "").trim();

  if (platformActor) {
    if (claimedLicenseeId || claimedOrganizationId) {
      throw new AdministrationAccessError("Platform actor tenant claims must be empty");
    }
  } else {
    if (!isUuid(claimedLicenseeId) || !isUuid(claimedOrganizationId)) {
      throw new AdministrationAccessError("Tenant administration scope is invalid");
    }
    if (targetLicenseeId && targetLicenseeId !== claimedLicenseeId) {
      throw new AdministrationAccessError("Requested tenant does not match the authenticated scope");
    }
    if (targetOrganizationId && targetOrganizationId !== claimedOrganizationId) {
      throw new AdministrationAccessError("Requested organization does not match the authenticated scope");
    }
  }
  if (targetLicenseeId && !isUuid(targetLicenseeId)) {
    throw new AdministrationAccessError("Target tenant identifier is invalid", 400);
  }
  if (targetOrganizationId && !isUuid(targetOrganizationId)) {
    throw new AdministrationAccessError("Target organization identifier is invalid", 400);
  }

  return {
    context: {
      userId,
      role: String(user.role),
      organizationId: platformActor ? targetOrganizationId || null : claimedOrganizationId,
      licenseeId: platformActor ? targetLicenseeId || null : claimedLicenseeId,
      manufacturerId: null,
      authAssurance: "mfa-verified",
      requestId,
      purpose: input.purpose,
    } satisfies CanonicalDbContext,
    platformActor,
  };
};

type QueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;
type JsonResultRow = { result: Prisma.JsonValue };

const requiredResult = <T>(rows: JsonResultRow[], command: string): T => {
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${command} returned an invalid database result`);
  }
  return result as T;
};

const json = (value: unknown) => JSON.stringify(value ?? {});

export const createLicenseeInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_create_licensee(${json(input)}::jsonb) AS result
    `,
    "create licensee"
  );

export const updateLicenseeInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_update_licensee(${json(input)}::jsonb) AS result
    `,
    "update licensee"
  );

export const deleteLicenseeInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_delete_licensee(${json(input)}::jsonb) AS result
    `,
    "delete licensee"
  );

export const createUserInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_create_user(${json(input)}::jsonb) AS result
    `,
    "create user"
  );

export const updateUserInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_update_user(${json(input)}::jsonb) AS result
    `,
    "update user"
  );

export const deleteUserInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_delete_user(${json(input)}::jsonb) AS result
    `,
    "delete user"
  );

export const restoreManufacturerInTransaction = async <T>(tx: QueryClient, input: Record<string, unknown>) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_restore_manufacturer(${json(input)}::jsonb) AS result
    `,
    "restore manufacturer"
  );

export const upsertManufacturerLicenseeLinkInTransaction = async <T>(
  tx: QueryClient,
  input: Record<string, unknown>
) =>
  requiredResult<T>(
    await tx.$queryRaw<JsonResultRow[]>`
      SELECT app_rls.session_c_upsert_manufacturer_licensee_link(${json(input)}::jsonb) AS result
    `,
    "upsert manufacturer licensee link"
  );

export const installAdministrationResultScope = async (
  tx: Pick<Prisma.TransactionClient, "$executeRaw">,
  context: CanonicalDbContext,
  scope: { licenseeId?: string | null; organizationId?: string | null }
) => {
  const licenseeId = String(scope.licenseeId || "").trim();
  const organizationId = String(scope.organizationId || "").trim();
  if (!isUuid(licenseeId) || !isUuid(organizationId)) {
    throw new AdministrationAccessError("Database administration result has invalid tenant scope", 500);
  }
  return installCanonicalDbContext(tx, {
    ...context,
    licenseeId,
    organizationId,
  });
};
