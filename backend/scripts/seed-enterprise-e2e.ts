import {
  Prisma,
  PrismaClient,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterLanguageKind,
  PrinterProfileStatus,
  PrinterTransportKind,
  PrinterTrustStatus,
  QRStatus,
  UserRole,
  UserStatus,
} from "@prisma/client";
import { createHash } from "crypto";

import { hashPassword } from "../src/services/auth/passwordService";

const prisma = new PrismaClient();

const IDS = {
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000102",
  superAdmin: "00000000-0000-4000-8000-000000000201",
  licenseeAdmin: "00000000-0000-4000-8000-000000000202",
  manufacturer: "00000000-0000-4000-8000-000000000203",
  sourceBatch: "00000000-0000-4000-8000-000000000301",
  printBatch: "00000000-0000-4000-8000-000000000302",
  verifyBatch: "00000000-0000-4000-8000-000000000303",
  printerRegistration: "00000000-0000-4000-8000-000000000401",
  printer: "00000000-0000-4000-8000-000000000402",
  printerProfile: "00000000-0000-4000-8000-000000000403",
};

const EMAILS = {
  superAdmin: String(process.env.E2E_SUPERADMIN_EMAIL || "e2e-super-admin@mscqr.example").trim().toLowerCase(),
  licenseeAdmin: String(process.env.E2E_LICENSEE_ADMIN_EMAIL || "e2e-licensee-admin@mscqr.example").trim().toLowerCase(),
  manufacturer: String(process.env.E2E_MANUFACTURER_EMAIL || "e2e-manufacturer@mscqr.example").trim().toLowerCase(),
};

const PASSWORDS = {
  superAdmin: String(process.env.E2E_SUPERADMIN_PASSWORD || ""),
  licenseeAdmin: String(process.env.E2E_LICENSEE_ADMIN_PASSWORD || ""),
  manufacturer: String(process.env.E2E_MANUFACTURER_PASSWORD || ""),
};

const BATCH_NAMES = {
  source: String(process.env.E2E_LICENSEE_BATCH_QUERY || "E2E Source Batch").trim() || "E2E Source Batch",
  print: String(process.env.E2E_MANUFACTURER_BATCH_QUERY || "E2E Manufacturer Print Batch").trim() || "E2E Manufacturer Print Batch",
  verify: "E2E Public Verification Batch",
};

const MANUFACTURER_NAME = String(process.env.E2E_ASSIGN_MANUFACTURER_NAME || "E2E Manufacturer").trim() || "E2E Manufacturer";
const PRINTER_NAME = String(process.env.E2E_PRINTER_PROFILE_NAME || "E2E Local Agent Printer").trim() || "E2E Local Agent Printer";
const VERIFY_CODE = String(process.env.E2E_VERIFY_CODE || "E2E0000000999").trim().toUpperCase();
const NATIVE_PRINTER_ID = "e2e-local-printer";

const requireSecret = (name: keyof typeof PASSWORDS, envName: string) => {
  const value = PASSWORDS[name];
  if (value.length < 12) {
    throw new Error(`${envName} must be provided by CI/test setup and be at least 12 characters.`);
  }
  return value;
};

const sourceCodes = Array.from({ length: 20 }, (_, index) => `E2E1000000${String(index + 1).padStart(3, "0")}`);
const printCodes = Array.from({ length: 10 }, (_, index) => `E2E2000000${String(index + 1).padStart(3, "0")}`);

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const now = () => new Date();

const upsertUser = async (params: {
  id: string;
  email: string;
  password: string;
  name: string;
  role: UserRole;
  orgId?: string | null;
  licenseeId?: string | null;
}) => {
  const passwordHash = await hashPassword(params.password);
  return prisma.user.upsert({
    where: { id: params.id },
    create: {
      id: params.id,
      email: params.email,
      passwordHash,
      name: params.name,
      role: params.role,
      orgId: params.orgId || null,
      licenseeId: params.licenseeId || null,
      status: UserStatus.ACTIVE,
      isActive: true,
      emailVerifiedAt: now(),
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
    update: {
      email: params.email,
      passwordHash,
      name: params.name,
      role: params.role,
      orgId: params.orgId || null,
      licenseeId: params.licenseeId || null,
      status: UserStatus.ACTIVE,
      isActive: true,
      disabledAt: null,
      disabledReason: null,
      deletedAt: null,
      emailVerifiedAt: now(),
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });
};

const upsertFreshAdminMfa = async (userId: string) => {
  const current = now();
  await prisma.adminMfaCredential.upsert({
    where: { userId },
    create: {
      userId,
      secretCiphertext: `e2e:${hash(`secret:${userId}`)}`,
      secretIv: `e2e:${hash(`iv:${userId}`).slice(0, 24)}`,
      secretTag: `e2e:${hash(`tag:${userId}`).slice(0, 32)}`,
      backupCodesHash: [],
      isEnabled: true,
      verifiedAt: current,
      lastUsedAt: current,
    },
    update: {
      isEnabled: true,
      verifiedAt: current,
      lastUsedAt: current,
      backupCodesHash: [],
    },
  });
};

const resetCodesForBatch = async (codes: string[], batchId: string, status: QRStatus) => {
  await prisma.qRCode.createMany({
    data: codes.map((code) => ({
      code,
      licenseeId: IDS.licensee,
      batchId,
      status,
      scanCount: 0,
      issuanceMode: "E2E_SEEDED",
    })),
    skipDuplicates: true,
  });

  await prisma.qRCode.updateMany({
    where: { code: { in: codes } },
    data: {
      licenseeId: IDS.licensee,
      batchId,
      status,
      scanCount: 0,
      scannedAt: null,
      printedAt: status === QRStatus.PRINTED ? now() : null,
      printedByUserId: status === QRStatus.PRINTED ? IDS.manufacturer : null,
      redeemedAt: null,
      blockedAt: null,
      underInvestigationAt: null,
      underInvestigationReason: null,
      printJobId: null,
      issuanceMode: status === QRStatus.PRINTED ? "GOVERNED_PRINT" : "E2E_SEEDED",
      customerVerifiableAt: status === QRStatus.PRINTED ? now() : null,
    },
  });
};

const seedPrinter = async () => {
  const heartbeatAt = now();
  await prisma.printerRegistration.upsert({
    where: { id: IDS.printerRegistration },
    create: {
      id: IDS.printerRegistration,
      userId: IDS.manufacturer,
      orgId: IDS.org,
      licenseeId: IDS.licensee,
      deviceFingerprint: "e2e-device-fingerprint",
      agentId: "e2e-agent",
      publicKeyPem: "compat:e2e-agent",
      certFingerprint: "e2e-mtls-fingerprint",
      trustStatus: PrinterTrustStatus.TRUSTED,
      approvedAt: heartbeatAt,
      lastSeenAt: heartbeatAt,
    },
    update: {
      userId: IDS.manufacturer,
      orgId: IDS.org,
      licenseeId: IDS.licensee,
      trustStatus: PrinterTrustStatus.TRUSTED,
      trustReason: null,
      revokedAt: null,
      approvedAt: heartbeatAt,
      lastSeenAt: heartbeatAt,
    },
  });

  await prisma.printerAttestation.deleteMany({ where: { printerRegistrationId: IDS.printerRegistration } });
  await prisma.printerAttestation.create({
    data: {
      printerRegistrationId: IDS.printerRegistration,
      signedPayloadHash: hash("e2e-local-agent-heartbeat"),
      heartbeatNonce: `e2e-${heartbeatAt.getTime()}`,
      attestedAt: heartbeatAt,
      expiresAt: new Date(heartbeatAt.getTime() + 10 * 60 * 1000),
      mtlsFingerprint: "e2e-mtls-fingerprint",
      signatureValid: true,
      trustValid: true,
      metadata: {
        connected: true,
        printerName: PRINTER_NAME,
        printerId: NATIVE_PRINTER_ID,
        selectedPrinterId: NATIVE_PRINTER_ID,
        selectedPrinterName: PRINTER_NAME,
        deviceName: "E2E Print Workstation",
        agentVersion: "e2e-ci",
        capabilitySummary: {
          transports: ["LOCAL_AGENT"],
          protocols: ["DRIVER_QUEUE"],
          languages: ["PDF"],
          supportsRaster: true,
          supportsPdf: true,
          dpiOptions: [203],
          mediaSizes: ["50x30mm"],
        },
        printers: [
          {
            printerId: NATIVE_PRINTER_ID,
            printerName: PRINTER_NAME,
            model: "E2E Driver Queue",
            connection: "LOCAL_AGENT",
            online: true,
            isDefault: true,
            protocols: ["DRIVER_QUEUE"],
            languages: ["PDF"],
            mediaSizes: ["50x30mm"],
            dpi: 203,
          },
        ],
      } as Prisma.InputJsonValue,
    },
  });

  await prisma.printer.upsert({
    where: { id: IDS.printer },
    create: {
      id: IDS.printer,
      name: PRINTER_NAME,
      vendor: "MSCQR",
      model: "E2E Driver Queue",
      connectionType: PrinterConnectionType.LOCAL_AGENT,
      commandLanguage: PrinterCommandLanguage.AUTO,
      nativePrinterId: NATIVE_PRINTER_ID,
      agentId: "e2e-agent",
      deviceFingerprint: "e2e-device-fingerprint",
      printerRegistrationId: IDS.printerRegistration,
      orgId: IDS.org,
      licenseeId: IDS.licensee,
      assignedUserId: IDS.manufacturer,
      createdByUserId: IDS.manufacturer,
      isActive: true,
      isDefault: true,
      lastSeenAt: heartbeatAt,
      lastValidatedAt: heartbeatAt,
      lastValidationStatus: "READY",
      lastValidationMessage: "E2E local agent is ready.",
    },
    update: {
      name: PRINTER_NAME,
      connectionType: PrinterConnectionType.LOCAL_AGENT,
      commandLanguage: PrinterCommandLanguage.AUTO,
      nativePrinterId: NATIVE_PRINTER_ID,
      agentId: "e2e-agent",
      deviceFingerprint: "e2e-device-fingerprint",
      printerRegistrationId: IDS.printerRegistration,
      orgId: IDS.org,
      licenseeId: IDS.licensee,
      assignedUserId: IDS.manufacturer,
      createdByUserId: IDS.manufacturer,
      isActive: true,
      isDefault: true,
      lastSeenAt: heartbeatAt,
      lastValidatedAt: heartbeatAt,
      lastValidationStatus: "READY",
      lastValidationMessage: "E2E local agent is ready.",
    },
  });

  await prisma.printerProfile.upsert({
    where: { printerId: IDS.printer },
    create: {
      id: IDS.printerProfile,
      printerId: IDS.printer,
      status: PrinterProfileStatus.CERTIFIED,
      transportKind: PrinterTransportKind.DRIVER_QUEUE,
      activeLanguage: PrinterLanguageKind.PDF,
      nativeLanguage: "PDF",
      supportedLanguages: ["PDF"] as Prisma.InputJsonValue,
      jobMode: "CUT_SHEET",
      spoolFormat: "PDF",
      brand: "MSCQR",
      modelName: "E2E Driver Queue",
      dpi: 203,
      lastVerifiedAt: heartbeatAt,
      lastCertifiedAt: heartbeatAt,
    },
    update: {
      status: PrinterProfileStatus.CERTIFIED,
      transportKind: PrinterTransportKind.DRIVER_QUEUE,
      activeLanguage: PrinterLanguageKind.PDF,
      nativeLanguage: "PDF",
      supportedLanguages: ["PDF"] as Prisma.InputJsonValue,
      jobMode: "CUT_SHEET",
      spoolFormat: "PDF",
      lastVerifiedAt: heartbeatAt,
      lastCertifiedAt: heartbeatAt,
    },
  });
};

const seed = async () => {
  const superAdminPassword = requireSecret("superAdmin", "E2E_SUPERADMIN_PASSWORD");
  const licenseeAdminPassword = requireSecret("licenseeAdmin", "E2E_LICENSEE_ADMIN_PASSWORD");
  const manufacturerPassword = requireSecret("manufacturer", "E2E_MANUFACTURER_PASSWORD");

  await prisma.organization.upsert({
    where: { id: IDS.org },
    create: { id: IDS.org, name: "E2E MSCQR Operations", isActive: true },
    update: { name: "E2E MSCQR Operations", isActive: true },
  });

  await prisma.licensee.upsert({
    where: { id: IDS.licensee },
    create: {
      id: IDS.licensee,
      orgId: IDS.org,
      name: "E2E Licensee",
      prefix: "E2E",
      brandName: "E2E Authentication Operations",
      supportEmail: "support@mscqr.example",
      isActive: true,
    },
    update: {
      name: "E2E Licensee",
      brandName: "E2E Authentication Operations",
      supportEmail: "support@mscqr.example",
      isActive: true,
      suspendedAt: null,
      suspendedReason: null,
    },
  });

  await upsertUser({
    id: IDS.superAdmin,
    email: EMAILS.superAdmin,
    password: superAdminPassword,
    name: "E2E Super Admin",
    role: UserRole.SUPER_ADMIN,
  });
  await upsertUser({
    id: IDS.licenseeAdmin,
    email: EMAILS.licenseeAdmin,
    password: licenseeAdminPassword,
    name: "E2E Licensee Admin",
    role: UserRole.LICENSEE_ADMIN,
    orgId: IDS.org,
    licenseeId: IDS.licensee,
  });
  await upsertUser({
    id: IDS.manufacturer,
    email: EMAILS.manufacturer,
    password: manufacturerPassword,
    name: MANUFACTURER_NAME,
    role: UserRole.MANUFACTURER,
    orgId: IDS.org,
    licenseeId: IDS.licensee,
  });

  await upsertFreshAdminMfa(IDS.superAdmin);
  await upsertFreshAdminMfa(IDS.licenseeAdmin);

  await prisma.manufacturerLicenseeLink.upsert({
    where: {
      manufacturerId_licenseeId: {
        manufacturerId: IDS.manufacturer,
        licenseeId: IDS.licensee,
      },
    },
    create: {
      manufacturerId: IDS.manufacturer,
      licenseeId: IDS.licensee,
      isPrimary: true,
    },
    update: { isPrimary: true },
  });

  await prisma.qRCode.updateMany({
    where: { code: { in: [...sourceCodes, ...printCodes, VERIFY_CODE] } },
    data: { printJobId: null },
  });
  await prisma.printJob.deleteMany({
    where: {
      OR: [
        { batchId: IDS.printBatch },
        { batchId: IDS.sourceBatch },
        { batch: { parentBatchId: IDS.sourceBatch } },
      ],
    },
  });

  await prisma.batch.upsert({
    where: { id: IDS.sourceBatch },
    create: {
      id: IDS.sourceBatch,
      name: BATCH_NAMES.source,
      licenseeId: IDS.licensee,
      startCode: sourceCodes[0],
      endCode: sourceCodes[sourceCodes.length - 1],
      totalCodes: sourceCodes.length,
    },
    update: {
      name: BATCH_NAMES.source,
      licenseeId: IDS.licensee,
      manufacturerId: null,
      parentBatchId: null,
      rootBatchId: null,
      startCode: sourceCodes[0],
      endCode: sourceCodes[sourceCodes.length - 1],
      totalCodes: sourceCodes.length,
      printedAt: null,
      suspendedAt: null,
      suspendedReason: null,
    },
  });

  await prisma.batch.upsert({
    where: { id: IDS.printBatch },
    create: {
      id: IDS.printBatch,
      name: BATCH_NAMES.print,
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      parentBatchId: IDS.sourceBatch,
      rootBatchId: IDS.sourceBatch,
      startCode: printCodes[0],
      endCode: printCodes[printCodes.length - 1],
      totalCodes: printCodes.length,
    },
    update: {
      name: BATCH_NAMES.print,
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      parentBatchId: IDS.sourceBatch,
      rootBatchId: IDS.sourceBatch,
      startCode: printCodes[0],
      endCode: printCodes[printCodes.length - 1],
      totalCodes: printCodes.length,
      printedAt: null,
      suspendedAt: null,
      suspendedReason: null,
    },
  });

  await prisma.batch.upsert({
    where: { id: IDS.verifyBatch },
    create: {
      id: IDS.verifyBatch,
      name: BATCH_NAMES.verify,
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      startCode: VERIFY_CODE,
      endCode: VERIFY_CODE,
      totalCodes: 1,
      printedAt: now(),
    },
    update: {
      name: BATCH_NAMES.verify,
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      startCode: VERIFY_CODE,
      endCode: VERIFY_CODE,
      totalCodes: 1,
      printedAt: now(),
      suspendedAt: null,
      suspendedReason: null,
    },
  });

  await resetCodesForBatch(sourceCodes, IDS.sourceBatch, QRStatus.ACTIVE);
  await resetCodesForBatch(printCodes, IDS.printBatch, QRStatus.ALLOCATED);
  await resetCodesForBatch([VERIFY_CODE], IDS.verifyBatch, QRStatus.PRINTED);

  await prisma.inventoryStatusRollup.upsert({
    where: { batchId: IDS.sourceBatch },
    create: {
      batchId: IDS.sourceBatch,
      licenseeId: IDS.licensee,
      totalCodes: sourceCodes.length,
      active: sourceCodes.length,
    },
    update: {
      licenseeId: IDS.licensee,
      manufacturerId: null,
      totalCodes: sourceCodes.length,
      dormant: 0,
      active: sourceCodes.length,
      activated: 0,
      allocated: 0,
      printed: 0,
      redeemed: 0,
      blocked: 0,
      scanned: 0,
      refreshedAt: now(),
    },
  });
  await prisma.inventoryStatusRollup.upsert({
    where: { batchId: IDS.printBatch },
    create: {
      batchId: IDS.printBatch,
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      totalCodes: printCodes.length,
      allocated: printCodes.length,
    },
    update: {
      licenseeId: IDS.licensee,
      manufacturerId: IDS.manufacturer,
      totalCodes: printCodes.length,
      dormant: 0,
      active: 0,
      activated: 0,
      allocated: printCodes.length,
      printed: 0,
      redeemed: 0,
      blocked: 0,
      scanned: 0,
      refreshedAt: now(),
    },
  });

  await seedPrinter();

  console.log(
    JSON.stringify({
      ok: true,
      seeded: {
        users: 3,
        licensee: "E2E Licensee",
        sourceBatch: BATCH_NAMES.source,
        manufacturerBatch: BATCH_NAMES.print,
        printer: PRINTER_NAME,
        verifyCode: VERIFY_CODE,
      },
    })
  );
};

seed()
  .catch((error) => {
    console.error("Enterprise E2E seed failed:", error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
