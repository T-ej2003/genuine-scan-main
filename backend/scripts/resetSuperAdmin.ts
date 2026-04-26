import prisma from "../src/config/database";
import { UserStatus } from "@prisma/client";
import { hashPassword } from "../src/services/auth/passwordService";
import { normalizeEmailAddress } from "../src/utils/email";

async function main() {
  const email = normalizeEmailAddress(process.env.SUPER_ADMIN_EMAIL);
  const newPassword = String(process.env.SUPER_ADMIN_RESET_PASSWORD || "");

  if (!email) {
    throw new Error("SUPER_ADMIN_EMAIL must be set to a valid email address.");
  }
  if (newPassword.length < 12) {
    throw new Error("SUPER_ADMIN_RESET_PASSWORD must be set and at least 12 characters.");
  }

  const hash = await hashPassword(newPassword);
  const verifiedAt = new Date();

  const user = await prisma.user.upsert({
    where: { email },
    update: {
      passwordHash: hash,
      role: "SUPER_ADMIN",
      status: UserStatus.ACTIVE,
      isActive: true,
      deletedAt: null,
      disabledAt: null,
      emailVerifiedAt: verifiedAt,
    },
    create: {
      email,
      name: "Super Admin",
      role: "SUPER_ADMIN",
      passwordHash: hash,
      status: UserStatus.ACTIVE,
      isActive: true,
      emailVerifiedAt: verifiedAt,
    },
    select: { id: true, email: true, role: true },
  });

  console.log("Super admin ready:", user);
}

main()
  .catch(console.error)
  .finally(async () => prisma.$disconnect());
