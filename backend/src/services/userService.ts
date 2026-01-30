import bcrypt from "bcryptjs";
import prisma from "../config/database";
import { UserRole } from "@prisma/client";

export async function createUser(params: {
  email: string;
  password: string;
  name: string;
  role: UserRole;
  licenseeId?: string | null;
}) {
  const passwordHash = await bcrypt.hash(params.password, 12);

  return prisma.user.create({
    data: {
      email: params.email.toLowerCase(),
      passwordHash,
      name: params.name,
      role: params.role,
      licenseeId: params.licenseeId ?? null,
      isActive: true,
      deletedAt: null,
    },
  });
}

