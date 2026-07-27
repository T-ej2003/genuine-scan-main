import { Prisma, UserRole } from "@prisma/client";

import type { CanonicalAssurance } from "../../../lib/canonicalDbContext";

type QueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;

export type RevalidatedAuthenticatedActor = {
  userId: string;
  role: UserRole;
  organizationId: string | null;
  licenseeId: string | null;
  manufacturerId: string | null;
  authAssurance: CanonicalAssurance;
};

const projection = ["authAssurance", "licenseeId", "manufacturerId", "organizationId", "role", "userId"];
const roles = new Set<string>(Object.values(UserRole));
const assurances = new Set<CanonicalAssurance>([
  "password-verified",
  "mfa-bootstrap",
  "mfa-verified",
  "step-up-verified",
]);

const required = (value: unknown, field: string, maximum = 191) => {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized || normalized.length > maximum) {
    throw new Error(`app_rls.revalidate_authenticated_actor returned an invalid ${field}`);
  }
  return normalized;
};

const optional = (value: unknown, field: string) =>
  value == null ? null : required(value, field);

export const revalidateAuthenticatedActor = async (
  db: QueryClient,
  input: {
    userId: string;
    sessionId: string;
    requestedLicenseeId: string | null;
    requestedOrganizationId: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  const userId = required(input.userId, "requested userId");
  const sessionId = required(input.sessionId, "requested sessionId");
  const requestedLicenseeId = optional(input.requestedLicenseeId, "requested licenseeId");
  const requestedOrganizationId = optional(input.requestedOrganizationId, "requested organizationId");
  if (!(input.checkedAt instanceof Date) || !Number.isFinite(input.checkedAt.getTime())) {
    throw new Error("app_rls.revalidate_authenticated_actor requires a valid checkedAt");
  }
  const requestId = required(input.requestId, "requestId", 128);
  const rows = await db.$queryRaw<RevalidatedAuthenticatedActor[]>`
    SELECT * FROM app_rls.revalidate_authenticated_actor(
      ${userId},
      ${sessionId},
      ${requestedLicenseeId},
      ${requestedOrganizationId},
      ${input.checkedAt}::timestamp without time zone,
      ${requestId}
    )
  `;
  if (rows.length > 1) throw new Error("app_rls.revalidate_authenticated_actor returned multiple actors");
  const actor = rows[0] || null;
  if (!actor) return null;
  const actual = Object.keys(actor).sort();
  if (actual.length !== projection.length || actual.some((key, index) => key !== projection[index])) {
    throw new Error("app_rls.revalidate_authenticated_actor returned an unexpected projection");
  }
  actor.userId = required(actor.userId, "userId");
  actor.role = required(actor.role, "role", 64) as UserRole;
  actor.organizationId = optional(actor.organizationId, "organizationId");
  actor.licenseeId = optional(actor.licenseeId, "licenseeId");
  actor.manufacturerId = optional(actor.manufacturerId, "manufacturerId");
  actor.authAssurance = required(actor.authAssurance, "authAssurance", 64) as CanonicalAssurance;
  if (actor.userId !== userId) throw new Error("app_rls.revalidate_authenticated_actor returned a foreign actor");
  if (!roles.has(actor.role)) throw new Error("app_rls.revalidate_authenticated_actor returned an unsupported role");
  if (!assurances.has(actor.authAssurance)) {
    throw new Error("app_rls.revalidate_authenticated_actor returned an unsupported assurance");
  }
  return actor;
};
