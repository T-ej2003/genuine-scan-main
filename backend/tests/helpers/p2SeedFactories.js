const path = require("path");
const fs = require("fs");
const JSZip = require("jszip");
const {
  IncidentPriority,
  IncidentSeverity,
  IncidentStatus,
  IncidentType,
  PrintDispatchMode,
  PrintJobStatus,
  PrintPipelineState,
  PrintPayloadType,
  QRStatus,
  UserRole,
  UserStatus,
} = require("@prisma/client");

const backendRoot = path.resolve(__dirname, "../..");
const compliancePackDir = path.join(backendRoot, "uploads/compliance-packs");

const ids = {
  orgA: "00000000-0000-4202-8000-000000000001",
  orgB: "00000000-0000-4202-8000-000000000002",
  licenseeA: "00000000-0000-4202-8100-000000000001",
  licenseeB: "00000000-0000-4202-8100-000000000002",
  superAdmin: "00000000-0000-4202-8200-000000000001",
  licenseeAdminA: "00000000-0000-4202-8200-000000000002",
  licenseeAdminB: "00000000-0000-4202-8200-000000000003",
  manufacturerA: "00000000-0000-4202-8200-000000000004",
  manufacturerB: "00000000-0000-4202-8200-000000000005",
  batchA: "00000000-0000-4202-8300-000000000001",
  batchB: "00000000-0000-4202-8300-000000000002",
  qrA: "00000000-0000-4202-8400-000000000001",
  qrB: "00000000-0000-4202-8400-000000000002",
  scanA: "00000000-0000-4202-8500-000000000001",
  scanB: "00000000-0000-4202-8500-000000000002",
  incidentA: "00000000-0000-4202-8600-000000000001",
  incidentB: "00000000-0000-4202-8600-000000000002",
  supportTicketA: "00000000-0000-4202-8700-000000000001",
  supportTicketB: "00000000-0000-4202-8700-000000000002",
  supportReportA: "00000000-0000-4202-8800-000000000001",
  supportReportB: "00000000-0000-4202-8800-000000000002",
  qrRequestA: "00000000-0000-4202-8900-000000000001",
  qrRequestB: "00000000-0000-4202-8900-000000000002",
  printJobA: "00000000-0000-4202-9000-000000000001",
  printJobB: "00000000-0000-4202-9000-000000000002",
  featureFlagA: "00000000-0000-4202-9100-000000000001",
  featureFlagB: "00000000-0000-4202-9100-000000000002",
  complianceJobA: "00000000-0000-4202-9200-000000000001",
  complianceJobB: "00000000-0000-4202-9200-000000000002",
  mfaSuperAdmin: "00000000-0000-4202-9300-000000000001",
  mfaLicenseeA: "00000000-0000-4202-9300-000000000002",
  mfaLicenseeB: "00000000-0000-4202-9300-000000000003",
};

const passwords = {
  superAdmin: "P2SuperAdmin!2345",
  licenseeAdminA: "P2LicenseeA!2345",
  licenseeAdminB: "P2LicenseeB!2345",
  manufacturerA: "P2ManufacturerA!2345",
  manufacturerB: "P2ManufacturerB!2345",
};

const emails = {
  superAdmin: "p2-super-admin@mscqr.test",
  licenseeAdminA: "p2-licensee-a@mscqr.test",
  licenseeAdminB: "p2-licensee-b@mscqr.test",
  manufacturerA: "p2-manufacturer-a@mscqr.test",
  manufacturerB: "p2-manufacturer-b@mscqr.test",
};

const p2UserIds = [ids.superAdmin, ids.licenseeAdminA, ids.licenseeAdminB, ids.manufacturerA, ids.manufacturerB];
const p2LicenseeIds = [ids.licenseeA, ids.licenseeB];

const loadDist = (relativePath) => require(path.join(backendRoot, "dist", relativePath));

const resetP2Fixtures = async (prisma) => {
  await prisma.refreshToken.deleteMany({ where: { userId: { in: p2UserIds } } });
  await prisma.batchPrintPackToken.deleteMany({ where: { batchId: { in: [ids.batchA, ids.batchB] } } });
  await prisma.supportTicketMessage.deleteMany({ where: { ticketId: { in: [ids.supportTicketA, ids.supportTicketB] } } });
  await prisma.supportTicket.deleteMany({ where: { id: { in: [ids.supportTicketA, ids.supportTicketB] } } });
  await prisma.supportIssueReport.deleteMany({ where: { id: { in: [ids.supportReportA, ids.supportReportB] } } });
  await prisma.incident.deleteMany({ where: { id: { in: [ids.incidentA, ids.incidentB] } } });
  await prisma.qrScanLog.deleteMany({ where: { id: { in: [ids.scanA, ids.scanB] } } });
  await prisma.qrAllocationRequest.deleteMany({ where: { id: { in: [ids.qrRequestA, ids.qrRequestB] } } });
  await prisma.compliancePackJob.deleteMany({ where: { id: { in: [ids.complianceJobA, ids.complianceJobB] } } });
  await prisma.tenantFeatureFlag.deleteMany({ where: { id: { in: [ids.featureFlagA, ids.featureFlagB] } } });
  await prisma.qRCode.deleteMany({ where: { id: { in: [ids.qrA, ids.qrB] } } });
  await prisma.printJob.deleteMany({ where: { id: { in: [ids.printJobA, ids.printJobB] } } });
  await prisma.batch.deleteMany({ where: { id: { in: [ids.batchA, ids.batchB] } } });
  await prisma.adminMfaCredential.deleteMany({ where: { userId: { in: p2UserIds } } });
  await prisma.manufacturerLicenseeLink.deleteMany({ where: { OR: [{ manufacturerId: { in: p2UserIds } }, { licenseeId: { in: p2LicenseeIds } }] } });
  await prisma.user.deleteMany({ where: { id: { in: p2UserIds } } });
  await prisma.licensee.deleteMany({ where: { id: { in: p2LicenseeIds } } });
  await prisma.organization.deleteMany({ where: { id: { in: [ids.orgA, ids.orgB] } } });

  for (const fileName of ["p2-a-pack.zip", "p2-b-pack.zip"]) {
    const filePath = path.join(compliancePackDir, fileName);
    if (fs.existsSync(filePath)) fs.rmSync(filePath, { force: true });
  }
};

const writeCompliancePackFixture = async (fileName, licenseeId, marker) => {
  fs.mkdirSync(compliancePackDir, { recursive: true });
  const zip = new JSZip();
  zip.file("compliance-report.json", JSON.stringify({ licenseeId, marker, controls: [] }, null, 2));
  zip.file("controls-map.json", JSON.stringify([], null, 2));
  zip.file("evidence-map.json", JSON.stringify([], null, 2));
  zip.file("integrity.json", JSON.stringify({ licenseeId, marker, fileHashes: {} }, null, 2));
  fs.writeFileSync(path.join(compliancePackDir, fileName), await zip.generateAsync({ type: "nodebuffer" }));
};

const createUser = async (prisma, hashPassword, key, role, licenseeId = null, orgId = null) =>
  prisma.user.create({
    data: {
      id: ids[key],
      email: emails[key],
      passwordHash: await hashPassword(passwords[key]),
      name: key.replace(/([A-Z])/g, " $1").replace(/^./, (value) => value.toUpperCase()),
      role,
      licenseeId,
      orgId,
      isActive: true,
      status: UserStatus.ACTIVE,
      emailVerifiedAt: new Date(),
    },
  });

const seedP2Fixtures = async (prisma) => {
  const { hashPassword } = loadDist("services/auth/passwordService");
  const { hashToken, signQrPayload } = loadDist("services/qrTokenService");

  await resetP2Fixtures(prisma);

  await prisma.organization.createMany({
    data: [
      { id: ids.orgA, name: "P2 Brand A Org", isActive: true },
      { id: ids.orgB, name: "P2 Brand B Org", isActive: true },
    ],
  });

  await prisma.licensee.createMany({
    data: [
      { id: ids.licenseeA, orgId: ids.orgA, name: "P2 Brand A", prefix: "P2A", brandName: "P2 Brand A", supportEmail: "support-a@mscqr.test" },
      { id: ids.licenseeB, orgId: ids.orgB, name: "P2 Brand B", prefix: "P2B", brandName: "P2 Brand B", supportEmail: "support-b@mscqr.test" },
    ],
  });

  await createUser(prisma, hashPassword, "superAdmin", UserRole.SUPER_ADMIN, null, null);
  await createUser(prisma, hashPassword, "licenseeAdminA", UserRole.LICENSEE_ADMIN, ids.licenseeA, ids.orgA);
  await createUser(prisma, hashPassword, "licenseeAdminB", UserRole.LICENSEE_ADMIN, ids.licenseeB, ids.orgB);
  await createUser(prisma, hashPassword, "manufacturerA", UserRole.MANUFACTURER, ids.licenseeA, ids.orgA);
  await createUser(prisma, hashPassword, "manufacturerB", UserRole.MANUFACTURER, ids.licenseeB, ids.orgB);

  await prisma.adminMfaCredential.createMany({
    data: [
      { id: ids.mfaSuperAdmin, userId: ids.superAdmin, secretCiphertext: "p2-test-ciphertext", secretIv: "p2-test-iv", secretTag: "p2-test-tag", backupCodesHash: [], isEnabled: true, verifiedAt: new Date(), lastUsedAt: new Date() },
      { id: ids.mfaLicenseeA, userId: ids.licenseeAdminA, secretCiphertext: "p2-test-ciphertext", secretIv: "p2-test-iv", secretTag: "p2-test-tag", backupCodesHash: [], isEnabled: true, verifiedAt: new Date(), lastUsedAt: new Date() },
      { id: ids.mfaLicenseeB, userId: ids.licenseeAdminB, secretCiphertext: "p2-test-ciphertext", secretIv: "p2-test-iv", secretTag: "p2-test-tag", backupCodesHash: [], isEnabled: true, verifiedAt: new Date(), lastUsedAt: new Date() },
    ],
  });

  await prisma.manufacturerLicenseeLink.createMany({
    data: [
      { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA, isPrimary: true },
      { manufacturerId: ids.manufacturerB, licenseeId: ids.licenseeB, isPrimary: true },
    ],
  });

  await prisma.batch.createMany({
    data: [
      { id: ids.batchA, name: "P2 Batch A", licenseeId: ids.licenseeA, manufacturerId: ids.manufacturerA, startCode: "P2A000001", endCode: "P2A000002", totalCodes: 2, printedAt: new Date() },
      { id: ids.batchB, name: "P2 Batch B", licenseeId: ids.licenseeB, manufacturerId: ids.manufacturerB, startCode: "P2B000001", endCode: "P2B000002", totalCodes: 2, printedAt: new Date() },
    ],
  });

  await prisma.printJob.createMany({
    data: [
      { id: ids.printJobA, jobNumber: "P2-PRINT-A", batchId: ids.batchA, manufacturerId: ids.manufacturerA, status: PrintJobStatus.CONFIRMED, printMode: PrintDispatchMode.LOCAL_AGENT, pipelineState: PrintPipelineState.PRINT_CONFIRMED, payloadType: PrintPayloadType.PDF, payloadHash: "p2-pack-a-hash", quantity: 2, itemCount: 2, rangeStart: "P2A000001", rangeEnd: "P2A000002", sentAt: new Date(), confirmedAt: new Date(), completedAt: new Date() },
      { id: ids.printJobB, jobNumber: "P2-PRINT-B", batchId: ids.batchB, manufacturerId: ids.manufacturerB, status: PrintJobStatus.CONFIRMED, printMode: PrintDispatchMode.LOCAL_AGENT, pipelineState: PrintPipelineState.PRINT_CONFIRMED, payloadType: PrintPayloadType.PDF, payloadHash: "p2-pack-b-hash", quantity: 2, itemCount: 2, rangeStart: "P2B000001", rangeEnd: "P2B000002", sentAt: new Date(), confirmedAt: new Date(), completedAt: new Date() },
    ],
  });

  await prisma.qRCode.createMany({
    data: [
      { id: ids.qrA, code: "P2A000001", licenseeId: ids.licenseeA, batchId: ids.batchA, printJobId: ids.printJobA, status: QRStatus.PRINTED, printedAt: new Date(), tokenNonce: "p2-scan-a-nonce", replayEpoch: 1, issuanceMode: "GOVERNED_PRINT", customerVerifiableAt: new Date() },
      { id: ids.qrB, code: "P2B000001", licenseeId: ids.licenseeB, batchId: ids.batchB, printJobId: ids.printJobB, status: QRStatus.PRINTED, printedAt: new Date(), tokenNonce: "p2-scan-b-nonce", replayEpoch: 1, issuanceMode: "GOVERNED_PRINT", customerVerifiableAt: new Date() },
    ],
  });

  const tokenA = signQrPayload({
    qr_id: ids.qrA,
    batch_id: ids.batchA,
    licensee_id: ids.licenseeA,
    manufacturer_id: ids.manufacturerA,
    epoch: 1,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: "p2-scan-a-nonce",
  });
  await prisma.qRCode.update({ where: { id: ids.qrA }, data: { tokenHash: hashToken(tokenA), tokenIssuedAt: new Date(), tokenExpiresAt: new Date(Date.now() + 3600_000) } });

  await prisma.qrScanLog.createMany({
    data: [
      { id: ids.scanA, code: "P2A000001", qrCodeId: ids.qrA, licenseeId: ids.licenseeA, batchId: ids.batchA, status: QRStatus.PRINTED, isFirstScan: true, scanCount: 1, ipAddress: "198.51.100.10", device: "p2-device-a" },
      { id: ids.scanB, code: "P2B000001", qrCodeId: ids.qrB, licenseeId: ids.licenseeB, batchId: ids.batchB, status: QRStatus.PRINTED, isFirstScan: true, scanCount: 1, ipAddress: "198.51.100.20", device: "p2-device-b" },
    ],
  });

  await prisma.incident.createMany({
    data: [
      { id: ids.incidentA, qrCodeId: ids.qrA, qrCodeValue: "P2A000001", scanEventId: ids.scanA, licenseeId: ids.licenseeA, incidentType: IncidentType.DUPLICATE_SCAN, severity: IncidentSeverity.HIGH, description: "P2 Tenant A suspicious scan", photos: [], tags: [], status: IncidentStatus.NEW, priority: IncidentPriority.P2 },
      { id: ids.incidentB, qrCodeId: ids.qrB, qrCodeValue: "P2B000001", scanEventId: ids.scanB, licenseeId: ids.licenseeB, incidentType: IncidentType.DUPLICATE_SCAN, severity: IncidentSeverity.HIGH, description: "P2 Tenant B suspicious scan", photos: [], tags: [], status: IncidentStatus.NEW, priority: IncidentPriority.P2 },
    ],
  });

  await prisma.supportTicket.createMany({
    data: [
      { id: ids.supportTicketA, incidentId: ids.incidentA, referenceCode: "P2SUPA", licenseeId: ids.licenseeA, customerEmail: "customer-a@mscqr.test", subject: "P2 Support A", status: "OPEN", priority: IncidentPriority.P2 },
      { id: ids.supportTicketB, incidentId: ids.incidentB, referenceCode: "P2SUPB", licenseeId: ids.licenseeB, customerEmail: "customer-b@mscqr.test", subject: "P2 Support B", status: "OPEN", priority: IncidentPriority.P2 },
    ],
  });

  await prisma.supportIssueReport.createMany({
    data: [
      { id: ids.supportReportA, reporterUserId: ids.manufacturerA, reporterRole: UserRole.MANUFACTURER, licenseeId: ids.licenseeA, title: "P2 Report A", description: "Tenant A issue", sourcePath: "/manufacturer/jobs" },
      { id: ids.supportReportB, reporterUserId: ids.manufacturerB, reporterRole: UserRole.MANUFACTURER, licenseeId: ids.licenseeB, title: "P2 Report B", description: "Tenant B issue", sourcePath: "/manufacturer/jobs" },
    ],
  });

  await prisma.qrAllocationRequest.createMany({
    data: [
      { id: ids.qrRequestA, licenseeId: ids.licenseeA, requestedByUserId: ids.licenseeAdminA, quantity: 50, batchName: "P2 Request A", note: "Tenant A allocation" },
      { id: ids.qrRequestB, licenseeId: ids.licenseeB, requestedByUserId: ids.licenseeAdminB, quantity: 50, batchName: "P2 Request B", note: "Tenant B allocation" },
    ],
  });

  await prisma.tenantFeatureFlag.createMany({
    data: [
      { id: ids.featureFlagA, licenseeId: ids.licenseeA, key: "p2-governance-a", enabled: true, updatedByUserId: ids.superAdmin },
      { id: ids.featureFlagB, licenseeId: ids.licenseeB, key: "p2-governance-b", enabled: true, updatedByUserId: ids.superAdmin },
    ],
  });

  await writeCompliancePackFixture("p2-a-pack.zip", ids.licenseeA, "p2-a-pack");
  await writeCompliancePackFixture("p2-b-pack.zip", ids.licenseeB, "p2-b-pack");

  await prisma.compliancePackJob.createMany({
    data: [
      { id: ids.complianceJobA, licenseeId: ids.licenseeA, status: "COMPLETED", triggerType: "P2_TEST", fileName: "p2-a-pack.zip", storageKey: "p2-a-pack.zip", integrityHash: "p2-a-integrity", startedByUserId: ids.superAdmin, finishedAt: new Date() },
      { id: ids.complianceJobB, licenseeId: ids.licenseeB, status: "COMPLETED", triggerType: "P2_TEST", fileName: "p2-b-pack.zip", storageKey: "p2-b-pack.zip", integrityHash: "p2-b-integrity", startedByUserId: ids.superAdmin, finishedAt: new Date() },
    ],
  });

  return { ids, emails, passwords, signedScanTokenA: tokenA };
};

const issueBearerTokens = async (userIds = ids) => {
  const { issueSessionForUser } = loadDist("services/auth/authService");
  const issue = async (userId, assurance = "PASSWORD") => {
    const session = await issueSessionForUser({
      userId,
      ipHash: "p2-test-ip",
      userAgent: "p2-test-agent",
      authAssurance: assurance,
      authenticatedAt: new Date(),
      mfaVerifiedAt: assurance === "ADMIN_MFA" ? new Date() : null,
      now: new Date(),
    });
    return session.accessToken;
  };
  return {
    superAdmin: await issue(userIds.superAdmin, "ADMIN_MFA"),
    licenseeAdminA: await issue(userIds.licenseeAdminA, "ADMIN_MFA"),
    licenseeAdminB: await issue(userIds.licenseeAdminB, "ADMIN_MFA"),
    manufacturerA: await issue(userIds.manufacturerA),
    manufacturerB: await issue(userIds.manufacturerB),
  };
};

module.exports = {
  emails,
  ids,
  issueBearerTokens,
  passwords,
  resetP2Fixtures,
  seedP2Fixtures,
};
