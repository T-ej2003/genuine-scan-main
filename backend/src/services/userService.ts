import prisma from "../config/database";
import { UserRole } from "@prisma/client";
import { hashPassword } from "./auth/passwordService";

export async function createUser(params: {
  email: string;
  password: string;
  name: string;
  role: UserRole;
  licenseeId?: string | null;
}) {
  const passwordHash = await hashPassword(params.password);

  const licenseeId = params.licenseeId ?? null;
  const orgId = licenseeId
    ? (
        await prisma.licensee.findUnique({
          where: { id: licenseeId },
          select: { orgId: true },
        })
      )?.orgId ?? null
    : null;

  return prisma.user.create({
    data: {
      email: params.email.toLowerCase(),
      passwordHash,
      emailVerifiedAt: new Date(),
      name: params.name,
      role: params.role,
      licenseeId,
      orgId,
      isActive: true,
      deletedAt: null,
    },
  });
}
