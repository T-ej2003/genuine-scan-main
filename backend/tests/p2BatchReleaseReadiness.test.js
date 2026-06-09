const assert = require("assert");
const { createHash, randomUUID } = require("crypto");
const {
  BatchLifecycleState,
  PrintDispatchMode,
  PrintItemState,
  PrintPayloadType,
  PrintPipelineState,
  PrintSessionStatus,
  PrintJobStatus,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterLanguageKind,
  PrinterProfileStatus,
  PrinterTransportKind,
  QRStatus,
  UserRole,
  UserStatus,
} = require("@prisma/client");
const { P2TestDbSkip, withP2TestApp } = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const authHeader = (token) => ({ authorization: `Bearer ${token}` });

const loadDist = (relativePath) => require(`../dist/${relativePath}`);

const hashPayload = (value) => createHash("sha256").update(value).digest("hex");

const issueTokenForUser = async (userId, assurance = "PASSWORD") => {
  const { issueSessionForUser } = loadDist("services/auth/authService");
  const session = await issueSessionForUser({
    userId,
    ipHash: "p2-release-approver-ip",
    userAgent: "p2-release-approver-agent",
    authAssurance: assurance,
    authenticatedAt: new Date(),
    mfaVerifiedAt: assurance === "ADMIN_MFA" ? new Date() : null,
    now: new Date(),
  });
  return session.accessToken;
};

const createUserWithToken = async (prisma, params) => {
  const { hashPassword } = loadDist("services/auth/passwordService");
  const id = randomUUID();
  await prisma.user.create({
    data: {
      id,
      email: `${params.emailPrefix}-${Date.now()}-${Math.floor(Math.random() * 10000)}@mscqr.test`,
      passwordHash: await hashPassword("P2GeneratedUser!2345"),
      name: params.name,
      role: params.role,
      orgId: params.orgId || null,
      licenseeId: params.licenseeId || null,
      status: UserStatus.ACTIVE,
      isActive: true,
      emailVerifiedAt: new Date(),
    },
  });
  if (params.linkLicenseeId) {
    await prisma.manufacturerLicenseeLink.create({
      data: {
        manufacturerId: id,
        licenseeId: params.linkLicenseeId,
        isPrimary: false,
      },
    });
  }
  return { id, token: await issueTokenForUser(id, params.assurance || "PASSWORD") };
};

const createSecondPlatformApprover = (prisma) =>
  createUserWithToken(prisma, {
    emailPrefix: "p2-second-approver",
    name: "P2 Second Approver",
    role: UserRole.SUPER_ADMIN,
    assurance: "ADMIN_MFA",
  });

const createZebraPrinterProfile = async (prisma, actorId, licenseeId, orgId) => {
  const printer = await prisma.printer.create({
    data: {
      name: `P2 Zebra ZT410 ${randomUUID()}`,
      vendor: "Zebra",
      model: "ZT410-300dpi",
      connectionType: PrinterConnectionType.NETWORK_DIRECT,
      commandLanguage: PrinterCommandLanguage.ZPL,
      host: "192.0.2.10",
      port: 9100,
      deliveryMode: "DIRECT",
      licenseeId,
      orgId,
      createdByUserId: actorId,
      isActive: true,
      isDefault: true,
      metadata: {
        testOnly: true,
        transport: "tcp_raw_9100",
      },
    },
  });

  await prisma.printerProfile.create({
    data: {
      printerId: printer.id,
      status: PrinterProfileStatus.CERTIFIED,
      transportKind: PrinterTransportKind.RAW_TCP,
      activeLanguage: PrinterLanguageKind.ZPL,
      nativeLanguage: "ZPL",
      supportedLanguages: ["ZPL"],
      jobMode: "RAW_SOCKET",
      preferredTransport: "tcp_raw_9100",
      brand: "Zebra",
      modelName: "ZT410",
      modelFamily: "ZT410",
      dpi: 300,
      statusConfig: {
        confirmationMode: "ZEBRA_ODOMETER",
      },
      mediaConstraints: {
        labelWidthDots: 600,
        labelLengthDots: 400,
      },
      renderingCapabilities: {
        qrCommand: "^BQN",
      },
      securityPosture: {
        publicCodeSource: "database_only",
      },
    },
  });

  return printer;
};

const createReadyBatchWithAcknowledgedPrintJob = async (prisma, params) => {
  const { generatePublicQRCode } = loadDist("services/qrService");
  const now = new Date();
  const quantity = params.quantity || 2;
  const suffix = String(params.startNumber || Math.floor(Math.random() * 1000000)).padStart(6, "0");
  const batch = await prisma.batch.create({
    data: {
      name: params.name,
      licenseeId: params.licenseeId,
      manufacturerId: params.manufacturerId,
      startCode: `P2${suffix}`,
      endCode: `P2${String(Number(suffix) + quantity - 1).padStart(6, "0")}`,
      totalCodes: quantity,
      lifecycleState: BatchLifecycleState.PRINT_ACKNOWLEDGED,
      sampleScanPolicy: { type: "ONE_PER_PRINT_JOB" },
    },
  });

  const qrRows = [];
  for (let index = 0; index < quantity; index += 1) {
    qrRows.push(
      await prisma.qRCode.create({
        data: {
          code: generatePublicQRCode(),
          displayCode: `P2T${suffix}${String(index + 1).padStart(3, "0")}`,
          licenseeId: params.licenseeId,
          batchId: batch.id,
          status: QRStatus.ACTIVATED,
          issuanceMode: "GOVERNED_PRINT",
          tokenNonce: `p2-release-${batch.id}-${index}`,
        },
      })
    );
  }

  const payloadHash = hashPayload(qrRows.map((row) => row.code).join("\n"));
  const printJob = await prisma.printJob.create({
    data: {
      jobNumber: `P2-REL-${randomUUID()}`,
      batchId: batch.id,
      manufacturerId: params.manufacturerId,
      printerId: params.printerId,
      status: PrintJobStatus.SENT,
      printMode: PrintDispatchMode.NETWORK_DIRECT,
      pipelineState: PrintPipelineState.PRINTER_ACKNOWLEDGED,
      payloadType: PrintPayloadType.ZPL,
      payloadHash,
      quantity,
      itemCount: quantity,
      rangeStart: qrRows[0].displayCode,
      rangeEnd: qrRows[qrRows.length - 1].displayCode,
      sentAt: now,
    },
  });

  await prisma.qRCode.updateMany({
    where: { id: { in: qrRows.map((row) => row.id) } },
    data: { printJobId: printJob.id },
  });

  const printSession = await prisma.printSession.create({
    data: {
      printJobId: printJob.id,
      batchId: batch.id,
      manufacturerId: params.manufacturerId,
      printerId: params.printerId,
      status: PrintSessionStatus.ACTIVE,
      totalItems: quantity,
      issuedItems: quantity,
    },
  });

  await prisma.printItem.createMany({
    data: qrRows.map((qr, index) => ({
      printSessionId: printSession.id,
      qrCodeId: qr.id,
      code: qr.code,
      state: PrintItemState.AGENT_ACKED,
      pipelineState: PrintPipelineState.PRINTER_ACKNOWLEDGED,
      issueSequence: index + 1,
      attemptCount: 1,
      dispatchedAt: now,
      agentAckedAt: now,
      deviceJobRef: `p2-ack-${index + 1}`,
      dispatchMetadata: {
        payloadType: PrintPayloadType.ZPL,
        payloadHash,
        bytesWritten: 128,
        p2NoRealPrinter: true,
      },
    })),
  });

  return { batch, qrRows, printJob, printSession };
};

const confirmScanAndRelease = async ({ request, tokens, batch, printJob, qrCode }) => {
  await confirmAndSample({ request, tokens, printJob, qrCode });

  const release = await request("POST", `/api/qr/batches/${batch.id}/release`, null, {
    headers: authHeader(tokens.manufacturerA),
  });
  assert.strictEqual(release.status, 200, release.text);
  assert.strictEqual(release.payload.data.batch.lifecycleState, BatchLifecycleState.RELEASED);
  return release;
};

const confirmAndSample = async ({ request, tokens, printJob, qrCode }) => {
  const confirm = await request(
    "POST",
    `/api/manufacturer/print-jobs/${printJob.id}/confirm`,
    { operatorNote: "P2 operator confirmed physical labels printed." },
    { headers: authHeader(tokens.manufacturerA) }
  );
  assert.strictEqual(confirm.status, 200, confirm.text);

  const sample = await request(
    "POST",
    `/api/manufacturer/print-jobs/${printJob.id}/sample-scan`,
    { publicCode: `https://www.mscqr.test/verify/${encodeURIComponent(qrCode.code)}` },
    { headers: authHeader(tokens.manufacturerA) }
  );
  assert.strictEqual(sample.status, 200, sample.text);
  assert.strictEqual(sample.payload.data.qrCodeId, qrCode.id, "sample scan should bind to the scanned QR");
};

const createHighValueApprovalRequest = async ({ request, tokens, prisma, printer, name, startNumber }) => {
  const high = await createReadyBatchWithAcknowledgedPrintJob(prisma, {
    name,
    licenseeId: ids.licenseeA,
    manufacturerId: ids.manufacturerA,
    printerId: printer.id,
    quantity: 2,
    startNumber,
  });
  await confirmAndSample({ request, tokens, printJob: high.printJob, qrCode: high.qrRows[0] });
  const response = await request("POST", `/api/qr/batches/${high.batch.id}/release`, null, {
    headers: authHeader(tokens.manufacturerA),
  });
  assert.strictEqual(response.status, 202, response.text);
  assert(response.payload.data.approvalId, "high-value release should create an approval request");
  return { ...high, approvalId: response.payload.data.approvalId };
};

let skipped = false;

(async () => {
  try {
    await withP2TestApp(async ({ request, prisma }) => {
      await seedP2Fixtures(prisma);
      const tokens = await issueBearerTokens();
      const secondApprover = await createSecondPlatformApprover(prisma);
      const printer = await createZebraPrinterProfile(prisma, ids.manufacturerA, ids.licenseeA, ids.orgA);

      process.env.BATCH_RELEASE_DUAL_APPROVAL_ENABLED = "false";

      const lifecycle = await createReadyBatchWithAcknowledgedPrintJob(prisma, {
        name: "P2 Release Readiness Batch",
        licenseeId: ids.licenseeA,
        manufacturerId: ids.manufacturerA,
        printerId: printer.id,
        quantity: 2,
        startNumber: 700001,
      });

      const other = await createReadyBatchWithAcknowledgedPrintJob(prisma, {
        name: "P2 Wrong Sample Batch",
        licenseeId: ids.licenseeA,
        manufacturerId: ids.manufacturerA,
        printerId: printer.id,
        quantity: 1,
        startNumber: 710001,
      });

      await request(
        "POST",
        `/api/manufacturer/print-jobs/${other.printJob.id}/confirm`,
        { operatorNote: "P2 other batch printed." },
        { headers: authHeader(tokens.manufacturerA) }
      );

      const confirmPrimary = await request(
        "POST",
        `/api/manufacturer/print-jobs/${lifecycle.printJob.id}/confirm`,
        { operatorNote: "P2 operator confirmed physical labels printed." },
        { headers: authHeader(tokens.manufacturerA) }
      );
      assert.strictEqual(confirmPrimary.status, 200, confirmPrimary.text);

      const wrongSample = await request(
        "POST",
        `/api/manufacturer/print-jobs/${lifecycle.printJob.id}/sample-scan`,
        { publicCode: other.qrRows[0].code },
        { headers: authHeader(tokens.manufacturerA) }
      );
      assert.strictEqual(wrongSample.status, 409, wrongSample.text);
      assert.match(wrongSample.text, /does not belong to this print job/i);

      const validSample = await request(
        "POST",
        `/api/manufacturer/print-jobs/${lifecycle.printJob.id}/sample-scan`,
        { publicCode: `https://www.mscqr.test/verify/${encodeURIComponent(lifecycle.qrRows[0].code)}` },
        { headers: authHeader(tokens.manufacturerA) }
      );
      assert.strictEqual(validSample.status, 200, validSample.text);

      const release = await request("POST", `/api/qr/batches/${lifecycle.batch.id}/release`, null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assert.strictEqual(release.status, 200, release.text);
      assert.strictEqual(release.payload.data.batch.lifecycleState, BatchLifecycleState.RELEASED);

      const released = await prisma.batch.findUnique({
        where: { id: lifecycle.batch.id },
        select: { lifecycleState: true, releasedAt: true, releasedByUserId: true },
      });
      assert.strictEqual(released.lifecycleState, BatchLifecycleState.RELEASED);
      assert(released.releasedAt, "releasedAt should be set");
      assert.strictEqual(released.releasedByUserId, ids.manufacturerA, "releasedBy should be the releasing operator");

      const releaseAudit = await prisma.printAuditEvent.findFirst({
        where: { batchId: lifecycle.batch.id, eventType: "batch_released" },
      });
      assert(releaseAudit, "batch_released print audit event should exist");

      const { assertQrPublicIdentityMutable } = loadDist("services/batchReleaseService");
      await assert.rejects(
        () => assertQrPublicIdentityMutable({ qrCodeId: lifecycle.qrRows[0].id }),
        /immutable after print, scan, release, or external exposure/i
      );

      const verify = await request("GET", `/api/verify/${encodeURIComponent(lifecycle.qrRows[0].code)}`, null);
      assert.strictEqual(verify.status, 200, verify.text);
      assert.strictEqual(verify.payload.data.isAuthentic, true, "released code should resolve as authentic");

      const evidence = await request("GET", `/api/qr/batches/${lifecycle.batch.id}/validation-evidence`, null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assert.strictEqual(evidence.status, 200, evidence.text);
      assert.strictEqual(evidence.payload.data.batch.id, lifecycle.batch.id);
      assert.strictEqual(evidence.payload.data.printJob.id, lifecycle.printJob.id);
      assert.strictEqual(evidence.payload.data.printer.transport, "tcp-raw");
      assert.strictEqual(evidence.payload.data.printer.port, 9100);
      assert.strictEqual(evidence.payload.data.verify.result, "authentic_released");
      assert(evidence.payload.data.auditEventIds.length > 0, "validation evidence should include audit event ids");
      assert(!evidence.text.includes("^XA"), "validation evidence must not expose raw ZPL");
      assert(!evidence.text.includes(lifecycle.qrRows[0].code), "validation evidence should mask public code by default");

      const foreignEvidence = await request("GET", `/api/qr/batches/${lifecycle.batch.id}/validation-evidence`, null, {
        headers: authHeader(tokens.licenseeAdminB),
      });
      assert.strictEqual(foreignEvidence.status, 404, foreignEvidence.text);

      const unknown = await request("GET", "/api/verify/c_unknown_p2_release_readiness", null);
      assert.strictEqual(unknown.status, 200, unknown.text);
      assert.strictEqual(unknown.payload.data.classification, "NOT_FOUND", "unknown code should stay not found");

      process.env.BATCH_RELEASE_DUAL_APPROVAL_ENABLED = "true";
      process.env.BATCH_RELEASE_DUAL_APPROVAL_QUANTITY_THRESHOLD = "2";

      const manufacturerChecker = await createUserWithToken(prisma, {
        emailPrefix: "p2-manufacturer-checker",
        name: "P2 Manufacturer Checker",
        role: UserRole.MANUFACTURER_ADMIN,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        linkLicenseeId: ids.licenseeA,
      });
      const normalOperator = await createUserWithToken(prisma, {
        emailPrefix: "p2-normal-operator",
        name: "P2 Normal Operator",
        role: UserRole.MANUFACTURER,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        linkLicenseeId: ids.licenseeA,
      });

      const high = await createHighValueApprovalRequest({
        request,
        tokens,
        prisma,
        printer,
        name: "P2 High Value Platform Approval Batch",
        startNumber: 720001,
      });
      const approvalId = high.approvalId;

      const stillPending = await prisma.batch.findUnique({
        where: { id: high.batch.id },
        select: { lifecycleState: true, releasedAt: true },
      });
      assert.notStrictEqual(stillPending.lifecycleState, BatchLifecycleState.RELEASED, "single user release should be blocked");
      assert.strictEqual(stillPending.releasedAt, null, "approval request must not release the batch");

      const sameUserApprove = await request(
        "POST",
        `/api/governance/approvals/${approvalId}/approve`,
        { note: "same user attempt" },
        { headers: authHeader(tokens.manufacturerA) }
      );
      assert.strictEqual(sameUserApprove.status, 400, sameUserApprove.text);
      assert.match(sameUserApprove.text, /cannot approve/i);

      const unauthorizedApprove = await request(
        "POST",
        `/api/governance/approvals/${approvalId}/approve`,
        { note: "normal operator attempt" },
        { headers: authHeader(normalOperator.token) }
      );
      assert.strictEqual(unauthorizedApprove.status, 400, unauthorizedApprove.text);
      assert.match(unauthorizedApprove.text, /cannot approve/i);

      const foreignLicenseeApprove = await request(
        "POST",
        `/api/governance/approvals/${approvalId}/approve`,
        { note: "foreign licensee attempt" },
        { headers: authHeader(tokens.licenseeAdminB) }
      );
      assert.strictEqual(foreignLicenseeApprove.status, 400, foreignLicenseeApprove.text);
      assert.match(foreignLicenseeApprove.text, /cannot approve/i);

      const approved = await request(
        "POST",
        `/api/governance/approvals/${approvalId}/approve`,
        { note: "second operator approved release" },
        { headers: authHeader(secondApprover.token) }
      );
      assert.strictEqual(approved.status, 200, approved.text);
      assert.strictEqual(approved.payload.data.approval.status, "EXECUTED");

      const highReleased = await prisma.batch.findUnique({
        where: { id: high.batch.id },
        select: { lifecycleState: true, releasedAt: true, releasedByUserId: true },
      });
      assert.strictEqual(highReleased.lifecycleState, BatchLifecycleState.RELEASED);
      assert(highReleased.releasedAt, "approved high-value batch should have releasedAt");
      assert.strictEqual(highReleased.releasedByUserId, secondApprover.id, "checker should be the final releaser");

      const grantedAudit = await prisma.printAuditEvent.findFirst({
        where: { batchId: high.batch.id, eventType: "batch_release_approval_granted" },
      });
      assert(grantedAudit, "approval granted audit event should exist");

      const licenseeApproval = await createHighValueApprovalRequest({
        request,
        tokens,
        prisma,
        printer,
        name: "P2 High Value Licensee Approval Batch",
        startNumber: 721001,
      });
      const licenseeApproved = await request(
        "POST",
        `/api/governance/approvals/${licenseeApproval.approvalId}/approve`,
        { note: "owning brand checker approved release" },
        { headers: authHeader(tokens.licenseeAdminA) }
      );
      assert.strictEqual(licenseeApproved.status, 200, licenseeApproved.text);

      const manufacturerApproval = await createHighValueApprovalRequest({
        request,
        tokens,
        prisma,
        printer,
        name: "P2 High Value Manufacturer Checker Batch",
        startNumber: 722001,
      });
      const manufacturerApproved = await request(
        "POST",
        `/api/governance/approvals/${manufacturerApproval.approvalId}/approve`,
        { note: "owning manufacturer checker approved release" },
        { headers: authHeader(manufacturerChecker.token) }
      );
      assert.strictEqual(manufacturerApproved.status, 200, manufacturerApproved.text);

      const rejectedBatch = await createReadyBatchWithAcknowledgedPrintJob(prisma, {
        name: "P2 High Value Rejected Batch",
        licenseeId: ids.licenseeA,
        manufacturerId: ids.manufacturerA,
        printerId: printer.id,
        quantity: 2,
        startNumber: 730001,
      });
      await confirmAndSample({ request, tokens, printJob: rejectedBatch.printJob, qrCode: rejectedBatch.qrRows[0] });
      const rejectRequest = await request("POST", `/api/qr/batches/${rejectedBatch.batch.id}/release`, null, {
        headers: authHeader(tokens.superAdmin),
      });
      assert.strictEqual(rejectRequest.status, 202, rejectRequest.text);
      const rejected = await request(
        "POST",
        `/api/governance/approvals/${rejectRequest.payload.data.approvalId}/reject`,
        { note: "release evidence rejected" },
        { headers: authHeader(secondApprover.token) }
      );
      assert.strictEqual(rejected.status, 200, rejected.text);
      const rejectedState = await prisma.batch.findUnique({
        where: { id: rejectedBatch.batch.id },
        select: { lifecycleState: true, releasedAt: true },
      });
      assert.notStrictEqual(rejectedState.lifecycleState, BatchLifecycleState.RELEASED, "rejection must block release");
      assert.strictEqual(rejectedState.releasedAt, null, "rejected release must not set releasedAt");
      const rejectionAudit = await prisma.printAuditEvent.findFirst({
        where: { batchId: rejectedBatch.batch.id, eventType: "batch_release_approval_rejected" },
      });
      assert(rejectionAudit, "approval rejected audit event should exist");
    }).catch((error) => {
      throw error;
    });
  } catch (error) {
    if (error instanceof P2TestDbSkip) {
      console.log(`p2 batch release readiness skipped: ${error.message}`);
      skipped = true;
      return;
    }
    throw error;
  }
})()
  .then(() => {
    if (!skipped) console.log("p2 batch release readiness tests passed");
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
