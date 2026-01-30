import prisma from "../src/config/database";
import bcrypt from "bcryptjs";

async function main() {
  const email = "admin@mcs.local";
  const newPassword = "Admin@1234";

  const hash = await bcrypt.hash(newPassword, 10);

  const user = await prisma.user.upsert({
    where: { email },
    update: {
      passwordHash: hash,
      role: "SUPER_ADMIN",
    },
    create: {
      email,
      name: "Super Admin",
      role: "SUPER_ADMIN",
      passwordHash: hash,
    },
    select: { id: true, email: true, role: true },
  });

  console.log("Super admin ready:", user);
}

main()
  .catch(console.error)
  .finally(async () => prisma.$disconnect());

