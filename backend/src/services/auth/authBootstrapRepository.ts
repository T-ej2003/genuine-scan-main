import { Prisma, UserRole, UserStatus } from "@prisma/client";

import prisma from "../../config/database";

type QueryClient = Pick<typeof prisma | Prisma.TransactionClient, "$queryRaw"> & {
  user: Pick<Prisma.TransactionClient["user"], "findMany">;
};

const isMissingAuthBoundary = (error: unknown) => {
  const candidate = error as { code?: unknown; meta?: { code?: unknown } } | null;
  return candidate?.code === "P2010" && ["3F000", "42883"].includes(String(candidate.meta?.code || ""));
};

const passwordBootstrapSelect = {
  id: true,
  email: true,
  passwordHash: true,
  name: true,
  role: true,
  licenseeId: true,
  orgId: true,
  status: true,
  isActive: true,
  disabledAt: true,
  deletedAt: true,
  failedLoginAttempts: true,
  lockedUntil: true,
  lastLoginAt: true,
  emailVerifiedAt: true,
} as const;

const findPreCandidatePasswordUser = async (normalizedEmail: string, db: QueryClient) => {
  const rows = await db.user.findMany({
    where: { email: { equals: normalizedEmail, mode: "insensitive" } },
    select: passwordBootstrapSelect,
    take: 2,
  });
  return rows.length === 1 ? rows[0] : null;
};

export type PasswordBootstrapUser = {
  id: string;
  email: string;
  passwordHash: string | null;
  name: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  status: UserStatus;
  isActive: boolean;
  disabledAt: Date | null;
  deletedAt: Date | null;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  emailVerifiedAt: Date | null;
};

export const lookupPasswordBootstrapUser = async (
  normalizedEmail: string,
  db: QueryClient = prisma
) => {
  try {
    const rows = await db.$queryRaw<PasswordBootstrapUser[]>`
      SELECT * FROM app_auth.lookup_password_user(${normalizedEmail})
    `;
    return rows[0] || null;
  } catch (error) {
    if (!isMissingAuthBoundary(error)) throw error;
    // Pre-candidate compatibility only. This query remains subject to normal
    // grants and RLS, so a forced User policy still fails closed.
    return findPreCandidatePasswordUser(normalizedEmail, db);
  }
};

export const recordPasswordLoginFailure = async (
  input: {
    normalizedEmail: string;
    attemptedAt: Date;
    maxAttempts: number;
    lockoutMinutes: number;
  },
  db: QueryClient = prisma
) => {
  try {
    const rows = await db.$queryRaw<Array<{ failedLoginAttempts: number; lockedUntil: Date | null }>>`
      SELECT * FROM app_auth.record_password_failure(
        ${input.normalizedEmail},
        ${input.attemptedAt}::timestamp without time zone,
        ${input.maxAttempts}::integer,
        ${input.lockoutMinutes}::integer
      )
    `;
    return rows[0] || null;
  } catch (error) {
    if (!isMissingAuthBoundary(error)) throw error;
    const rows = await db.$queryRaw<Array<{ failedLoginAttempts: number; lockedUntil: Date | null }>>`
      UPDATE public."User" u
      SET
        "failedLoginAttempts" = u."failedLoginAttempts" + 1,
        "lockedUntil" = CASE
          WHEN u."failedLoginAttempts" + 1 >= ${input.maxAttempts}::integer
            THEN ${input.attemptedAt}::timestamp without time zone
              + pg_catalog.make_interval(mins => ${input.lockoutMinutes}::integer)
          ELSE u."lockedUntil"
        END,
        "updatedAt" = ${input.attemptedAt}::timestamp without time zone
      WHERE u."id" = (
        SELECT pg_catalog.min(candidate."id")
        FROM public."User" candidate
        WHERE pg_catalog.lower(candidate."email") = ${input.normalizedEmail}
        HAVING pg_catalog.count(*) = 1
      )
      RETURNING u."failedLoginAttempts", u."lockedUntil"
    `;
    return rows[0] || null;
  }
};
