const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { PrismaClient, UserRole, UserStatus } = require("@prisma/client");
const argon2 = require("argon2");

const prisma = new PrismaClient();

async function main() {
  const [emailArg, passwordArg, nameArg] = process.argv.slice(2);

  const email = String(emailArg || "").trim().toLowerCase();
  const password = String(passwordArg || "").trim();
  const name = String(nameArg || email.split("@")[0] || "Super Admin").trim();

  if (!email || !password) {
    console.log("Usage: node scripts/create-super-admin.js <email> <password> [name]");
    process.exit(1);
  }

  if (password.length < 12) {
    console.error("Password must be at least 12 characters.");
    process.exit(1);
  }

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
  const verifiedAt = new Date();

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const updated = await prisma.user.update({
      where: { email },
      data: {
        name,
        role: UserRole.SUPER_ADMIN,
        passwordHash,
        status: UserStatus.ACTIVE,
        isActive: true,
        deletedAt: null,
        disabledAt: null,
        emailVerifiedAt: existing.emailVerifiedAt || verifiedAt,
      },
      select: { id: true, email: true, name: true, role: true },
    });
    console.log("Updated user to SUPER_ADMIN:", updated);
    return;
  }

  const created = await prisma.user.create({
    data: {
      email,
      passwordHash,
      name,
      role: UserRole.SUPER_ADMIN,
      status: UserStatus.ACTIVE,
      isActive: true,
      deletedAt: null,
      disabledAt: null,
      emailVerifiedAt: verifiedAt,
    },
    select: { id: true, email: true, name: true, role: true },
  });

  console.log("Created SUPER_ADMIN:", created);
}

main()
  .catch((e) => {
    console.error("Create super admin failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
