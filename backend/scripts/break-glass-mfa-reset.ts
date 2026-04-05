import os from "os";
import path from "path";

import dotenv from "dotenv";
import { UserRole } from "@prisma/client";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

import prisma from "../src/config/database";
import { createAuditLog } from "../src/services/auditService";
import { disableAdminMfa } from "../src/services/auth/mfaService";
import { revokeAllUserRefreshTokens } from "../src/services/auth/refreshTokenService";

const readArg = (name: string) => {
  const flag = `--${name}`;
  const index = process.argv.findIndex((entry) => entry === flag);
  if (index < 0) return "";
  return String(process.argv[index + 1] || "").trim();
};

const run = async () => {
  const email = readArg("email").toLowerCase();
  const reason = readArg("reason") || "Break-glass MFA recovery";

  if (!email) {
    throw new Error("Usage: tsx scripts/break-glass-mfa-reset.ts --email admin@example.com --reason \"Why this was needed\"");
  }

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      role: true,
      licenseeId: true,
      orgId: true,
    },
  });

  if (!user) {
    throw new Error(`No user found for ${email}`);
  }

  if (user.role !== UserRole.SUPER_ADMIN && user.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    throw new Error("Break-glass MFA reset is restricted to platform admin accounts.");
  }

  await disableAdminMfa(user.id);
  await revokeAllUserRefreshTokens({
    userId: user.id,
    reason: "BREAK_GLASS_MFA_RESET",
  });

  await createAuditLog({
    userId: user.id,
    licenseeId: user.licenseeId || undefined,
    orgId: user.orgId || undefined,
    action: "AUTH_MFA_BREAK_GLASS_RESET",
    entityType: "User",
    entityId: user.id,
    details: {
      email: user.email,
      role: user.role,
      reason,
      host: os.hostname(),
      invokedBy: "HOST_COMMAND",
    },
  } as any);

  console.log(`Break-glass MFA reset completed for ${user.email}`);
};

run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
