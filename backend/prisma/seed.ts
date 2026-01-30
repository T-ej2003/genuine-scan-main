import { PrismaClient, UserRole, QRStatus } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting seed...');

  // -----------------------------
  // Super Admin
  // -----------------------------
  const superAdminPassword = await bcrypt.hash('admin123', 10);
  const superAdmin = await prisma.user.upsert({
    where: { email: 'admin@authenticqr.com' },
    update: {},
    create: {
      email: 'admin@authenticqr.com',
      passwordHash: superAdminPassword,
      name: 'Super Admin',
      role: UserRole.SUPER_ADMIN,
    },
  });
  console.log('✅ Super Admin created:', superAdmin.email);

  // -----------------------------
  // Licensees
  // -----------------------------
  const licenseeA = await prisma.licensee.upsert({
    where: { prefix: 'A' },
    update: {},
    create: {
      name: 'Acme Corporation',
      prefix: 'A',
      description: 'Global manufacturing company',
    },
  });
  console.log('✅ Licensee A created:', licenseeA.name);

  const licenseeB = await prisma.licensee.upsert({
    where: { prefix: 'B' },
    update: {},
    create: {
      name: 'Beta Industries',
      prefix: 'B',
      description: 'Industrial supplies manufacturer',
    },
  });
  console.log('✅ Licensee B created:', licenseeB.name);

  // -----------------------------
  // Licensee Admins
  // -----------------------------
  const licenseeAdminPassword = await bcrypt.hash('licensee123', 10);

  const licenseeAdminA = await prisma.user.upsert({
    where: { email: 'admin@acme.com' },
    update: {},
    create: {
      email: 'admin@acme.com',
      passwordHash: licenseeAdminPassword,
      name: 'Acme Admin',
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: licenseeA.id,
    },
  });
  console.log('✅ Licensee Admin A created:', licenseeAdminA.email);

  const licenseeAdminB = await prisma.user.upsert({
    where: { email: 'admin@beta.com' },
    update: {},
    create: {
      email: 'admin@beta.com',
      passwordHash: licenseeAdminPassword,
      name: 'Beta Admin',
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: licenseeB.id,
    },
  });
  console.log('✅ Licensee Admin B created:', licenseeAdminB.email);

  // -----------------------------
  // Manufacturers
  // -----------------------------
  const manufacturerPassword = await bcrypt.hash('manufacturer123', 10);

  const manufacturerA1 = await prisma.user.upsert({
    where: { email: 'factory1@acme.com' },
    update: {},
    create: {
      email: 'factory1@acme.com',
      passwordHash: manufacturerPassword,
      name: 'Acme Factory 1',
      role: UserRole.MANUFACTURER,
      licenseeId: licenseeA.id,
    },
  });
  console.log('✅ Manufacturer A1 created:', manufacturerA1.email);

  const manufacturerA2 = await prisma.user.upsert({
    where: { email: 'factory2@acme.com' },
    update: {},
    create: {
      email: 'factory2@acme.com',
      passwordHash: manufacturerPassword,
      name: 'Acme Factory 2',
      role: UserRole.MANUFACTURER,
      licenseeId: licenseeA.id,
    },
  });
  console.log('✅ Manufacturer A2 created:', manufacturerA2.email);

  // -----------------------------
  // QR Range
  // -----------------------------
  const qrRange = await prisma.qRRange.upsert({
    where: { id: 'seed-range-a' },
    update: {},
    create: {
      id: 'seed-range-a',
      licenseeId: licenseeA.id,
      startCode: 'A0000000001',
      endCode: 'A0000001000',
      totalCodes: 1000,
    },
  });
  console.log('✅ QR Range created:', qrRange.startCode, '-', qrRange.endCode);

  // -----------------------------
  // QR Codes
  // -----------------------------
  const qrCodes: { code: string; licenseeId: string; status: QRStatus }[] = [];

  for (let i = 1; i <= 100; i++) {
    qrCodes.push({
      code: `A${i.toString().padStart(10, '0')}`,
      licenseeId: licenseeA.id,
      status: i <= 50 ? QRStatus.DORMANT : QRStatus.ACTIVE,
    });
  }

  await prisma.qRCode.createMany({
    data: qrCodes,
    skipDuplicates: true,
  });
  console.log('✅ Sample QR codes created: 100');

  // -----------------------------
  // Batch
  // -----------------------------
  const batch = await prisma.batch.upsert({
    where: { id: 'seed-batch-1' },
    update: {},
    create: {
      id: 'seed-batch-1',
      name: 'Batch 2024-001',
      licenseeId: licenseeA.id,
      manufacturerId: manufacturerA1.id,
      startCode: 'A0000000051',
      endCode: 'A0000000100',
      totalCodes: 50,
    },
  });
  console.log('✅ Sample batch created:', batch.name);

  await prisma.qRCode.updateMany({
    where: {
      code: {
        gte: 'A0000000051',
        lte: 'A0000000100',
      },
    },
    data: {
      batchId: batch.id,
      status: QRStatus.ALLOCATED,
    },
  });
  console.log('✅ QR codes allocated to batch');

  // -----------------------------
  // Audit Log (NO userName field!)
  // -----------------------------
  await prisma.auditLog.create({
    data: {
      userId: superAdmin.id,
      action: 'SEED_INIT',
      details: 'Initial database seed completed',
      ipAddress: '127.0.0.1',
      entityType: 'SYSTEM',
      entityId: 'seed',
    },
  });
  console.log('✅ Audit log created');

  console.log('\n📋 Seed completed! Login credentials:');
  console.log('------------------------------------------');
  console.log('Super Admin:     admin@authenticqr.com / admin123');
  console.log('Licensee Admin:  admin@acme.com / licensee123');
  console.log('Licensee Admin:  admin@beta.com / licensee123');
  console.log('Manufacturer:    factory1@acme.com / manufacturer123');
  console.log('------------------------------------------');
}

main()
  .catch((e) => {
    console.error('❌ Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

