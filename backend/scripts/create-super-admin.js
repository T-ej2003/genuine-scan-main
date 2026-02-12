const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { PrismaClient, UserRole } = require("@prisma/client");
const bcrypt = require("bcryptjs");

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

  const passwordHash = await bcrypt.hash(password, 10);

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const updated = await prisma.user.update({
      where: { email },
      data: {
        name,
        role: UserRole.SUPER_ADMIN,
        passwordHash,
        isActive: true,
        deletedAt: null,
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
      isActive: true,
      deletedAt: null,
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
