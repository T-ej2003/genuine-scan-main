const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { PrismaClient, UserRole } = require("@prisma/client");

const prisma = new PrismaClient();

const uniq = (arr) => Array.from(new Set(arr));

async function main() {
  const demoEmails = [
    "admin@mscqr.com",
    "admin@acme.com",
    "admin@beta.com",
    "factory1@acme.com",
    "factory2@acme.com",
  ];

  const demoLicenseeNames = ["Acme Corporation", "Beta Industries"];
  const demoPrefixes = ["A", "B"];

  const demoUsers = await prisma.user.findMany({
    where: { email: { in: demoEmails } },
    select: { id: true, email: true, role: true, licenseeId: true },
  });

  const licenseeIdsFromUsers = demoUsers
    .map((u) => u.licenseeId)
    .filter(Boolean);

  const demoLicensees = await prisma.licensee.findMany({
    where: {
      OR: [
        { id: { in: licenseeIdsFromUsers } },
        { name: { in: demoLicenseeNames } },
        { prefix: { in: demoPrefixes } },
      ],
    },
    select: { id: true, name: true, prefix: true },
  });

  const demoLicenseeIds = uniq(demoLicensees.map((l) => l.id));

  if (demoLicenseeIds.length === 0 && demoUsers.length === 0) {
    console.log("No demo data found to remove.");
    return;
  }

  const relatedUsers = await prisma.user.findMany({
    where: {
      OR: [
        { id: { in: demoUsers.map((u) => u.id) } },
        { licenseeId: { in: demoLicenseeIds } },
      ],
    },
    select: { id: true, email: true, role: true },
  });

  const demoUserIds = uniq(relatedUsers.map((u) => u.id));
  const demoSuperAdmins = relatedUsers.filter((u) => u.role === UserRole.SUPER_ADMIN);

  const otherSuperAdminCount = await prisma.user.count({
    where: {
      role: UserRole.SUPER_ADMIN,
      id: { notIn: demoSuperAdmins.map((u) => u.id) },
    },
  });

  const preserveSuperAdmins = otherSuperAdminCount === 0;
  const deletableUserIds = preserveSuperAdmins
    ? demoUserIds.filter((id) => !demoSuperAdmins.some((u) => u.id === id))
    : demoUserIds;

  console.log("Demo licensees:", demoLicensees);
  console.log("Demo users:", relatedUsers);
  if (preserveSuperAdmins && demoSuperAdmins.length) {
    console.log(
      "Preserving demo super admin(s) because no other SUPER_ADMIN exists:",
      demoSuperAdmins.map((u) => u.email)
    );
  }

  await prisma.qrScanLog.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.batchPrintPackToken.deleteMany({
    where: { batch: { licenseeId: { in: demoLicenseeIds } } },
  });

  await prisma.printJob.deleteMany({
    where: { batch: { licenseeId: { in: demoLicenseeIds } } },
  });

  await prisma.qRCode.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.batch.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.qRRange.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.qrAllocationRequest.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.allocationEvent.deleteMany({
    where: { licenseeId: { in: demoLicenseeIds } },
  });

  await prisma.auditLog.deleteMany({
    where: {
      OR: [
        { licenseeId: { in: demoLicenseeIds } },
        { userId: { in: demoUserIds } },
        { action: "SEED_INIT" },
        { entityId: "seed" },
      ],
    },
  });

  if (deletableUserIds.length) {
    await prisma.user.deleteMany({ where: { id: { in: deletableUserIds } } });
  }

  if (demoLicenseeIds.length) {
    await prisma.licensee.deleteMany({ where: { id: { in: demoLicenseeIds } } });
  }

  console.log("Demo cleanup completed.");
}

main()
  .catch((e) => {
    console.error("Demo cleanup failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
