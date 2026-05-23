const { sanitizePrinterActionError } = require("../dist/utils/printerUserFacingErrors");
const {
  buildPrintJobErrorPayload,
  describePrintJobCreateFailure,
  describeMissingPrinterReadinessFields,
} = require("../dist/controllers/print-job/errorResponses");
const { createPrintJobSchema } = require("../dist/controllers/print-job/shared");
const {
  hasExactTrustedSelectedPrinterMatch,
  pickSafeHeartbeatPrinterForProfile,
} = require("../dist/services/localAgentPrinterMappingService");
const { assessLocalAgentPrinterRelink } = require("../dist/services/localAgentPrinterRelinkService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const duplicateError =
    "Invalid `prisma.printer.create()` invocation: Unique constraint failed on the fields: (`licenseeId`, `ipAddress`, `port`)";

  assert(
    sanitizePrinterActionError(duplicateError) ===
      "A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.",
    "Duplicate printer endpoint errors should be redacted into a business-safe message"
  );

  assert(
    sanitizePrinterActionError("The browser could not reach localhost:17866") ===
      "The workstation connector is not available on this device right now.",
    "Localhost errors should be redacted"
  );

  assert(
    sanitizePrinterActionError("Label sent to Windows spooler, but Get-PrintJob rejected print job id as UInt32.") ===
      "Label was sent to Windows spooler but confirmation failed.",
    "Windows queue confirmation failures should not be reported as setup incompatibility"
  );

  const missingFields = describeMissingPrinterReadinessFields({
    connected: false,
    eligibleForPrinting: false,
    stale: true,
  });
  assert(missingFields.includes("printerRegistration"), "Missing registration should be reported as a safe field");
  assert(missingFields.includes("freshHelperHeartbeat"), "Stale helper heartbeat should be reported as a safe field");
  assert(missingFields.includes("helperConnection"), "Missing helper connection should be reported as a safe field");
  assert(missingFields.includes("eligiblePrinter"), "Missing eligible printer should be reported as a safe field");

  const payload = buildPrintJobErrorPayload({
    code: "missing_printer_session",
    message: "Refresh the printer connection, then start the print run again.",
    details: { missingFields },
  });
  assert(payload.success === false, "Print-job error payload should be an explicit failure");
  assert(payload.code === "missing_printer_session", "Print-job error payload should expose a stable code");
  assert(payload.errorCode === "missing_printer_session", "Print-job error payload should expose a stable errorCode");
  assert(payload.message === payload.error, "Print-job error payload should preserve API-client compatibility");
  assert(!JSON.stringify(payload).includes("localhost"), "Print-job error payload should not leak local internals");

  const missingSessionFailure = describePrintJobCreateFailure(
    Object.assign(new Error("PRINTER_NOT_TRUSTED"), {
      printerStatus: {
        connected: false,
        eligibleForPrinting: false,
        stale: true,
      },
    })
  );
  assert(missingSessionFailure.status === 409, "Missing printer sessions should be a conflict");
  assert(
    missingSessionFailure.payload.errorCode === "missing_printer_session",
    "Missing printer sessions should use a structured error code"
  );

  const batchFailure = describePrintJobCreateFailure(new Error("NOT_ENOUGH_CODES:0"));
  assert(batchFailure.status === 400, "Empty batches should be rejected as a bad print request");
  assert(batchFailure.payload.errorCode === "batch_not_printable", "Empty batches should have a printable-state code");

  const unsupportedPrinterFailure = describePrintJobCreateFailure(new Error("PRINTER_MODE_UNSUPPORTED"));
  assert(unsupportedPrinterFailure.status === 400, "Unsupported printer modes should be rejected safely");
  assert(
    unsupportedPrinterFailure.payload.errorCode === "unsupported_printer_route",
    "Unsupported printer modes should use a precise route code"
  );

  const validPayload = createPrintJobSchema.safeParse({
    batchId: "c9dabd08-9393-4be3-bb33-0269b543285d",
    printerId: "62eea666-5a7f-444a-94fb-8fa040396874",
    quantity: 2,
  });
  assert(validPayload.success, "Numeric print quantities and printer profile UUID payloads should be accepted");

  const invalidPayload = createPrintJobSchema.safeParse({
    batchId: "c9dabd08-9393-4be3-bb33-0269b543285d",
    printerId: "62eea666-5a7f-444a-94fb-8fa040396874",
    quantity: "2",
  });
  assert(!invalidPayload.success, "invalid_payload should remain reserved for true schema errors");

  const mappingFailure = describePrintJobCreateFailure(
    Object.assign(new Error("PRINTER_MAPPING_MISSING"), {
      printerStatus: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "ZDesigner ZT410-300dpi ZPL",
      },
    })
  );
  assert(mappingFailure.status === 409, "Missing printer mappings should be a conflict");
  assert(
    mappingFailure.payload.errorCode === "printer_mapping_missing",
    "Missing printer mappings should not be collapsed into invalid_payload"
  );

  const virtualSelectionFailure = describePrintJobCreateFailure(
    Object.assign(new Error("PRINTER_SELECTION_MISMATCH"), {
      printerStatus: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "Fax",
        selectedPrinterName: "Fax",
      },
    })
  );
  assert(
    virtualSelectionFailure.payload.errorCode === "printer_selection_mismatch",
    "Virtual selections should expose the exact selection mismatch"
  );
  assert(
    virtualSelectionFailure.payload.message ===
      "Fax/PDF printers cannot be used for MSCQR labels. Choose the ZDesigner label printer.",
    "Virtual printer mismatch should return specific copy"
  );

  const printerNotFoundFailure = describePrintJobCreateFailure(new Error("PRINTER_NOT_FOUND"));
  assert(printerNotFoundFailure.status === 404, "Missing printer profiles should return not found");
  assert(
    printerNotFoundFailure.payload.errorCode === "printer_not_found",
    "Missing printer profiles should not be collapsed into invalid_printer"
  );

  const transactionFailure = describePrintJobCreateFailure(Object.assign(new Error("Foreign key failed"), { code: "P2003" }));
  assert(transactionFailure.status === 409, "Transaction constraint failures should be conflicts");
  assert(
    transactionFailure.payload.errorCode === "print_job_transaction_failed",
    "Transaction failures should not be collapsed into invalid_payload"
  );

  const reservationFailure = describePrintJobCreateFailure(
    Object.assign(new Error("Duplicate print item"), { code: "P2002", meta: { target: ["qrCodeId"] } })
  );
  assert(
    reservationFailure.payload.errorCode === "print_item_reservation_failed",
    "Reservation conflicts should use a precise print item code"
  );
  assert(
    /locked by a failed print run/i.test(reservationFailure.payload.message),
    "Reservation conflicts should tell operators how to recover"
  );

  const unknownFailure = describePrintJobCreateFailure(new Error("Unexpected downstream failure"));
  assert(unknownFailure.status === 500, "Unknown downstream failures should be internal failures");
  assert(
    unknownFailure.payload.errorCode === "internal_print_job_create_failed",
    "Unknown downstream failures should never be invalid_payload after validation"
  );

  const signingFailure = describePrintJobCreateFailure(
    Object.assign(new Error("QR signing key configuration is invalid"), {
      code: "QR_SIGNING_CONFIGURATION_INVALID",
      safeCryptoMetadata: {
        operation: "key_import",
        mode: "ed25519",
        provider: "env",
        keySourceLabel: "env:QR_SIGN_PRIVATE_KEY/QR_SIGN_PUBLIC_KEY",
        errorCode: "ERR_OSSL_UNSUPPORTED",
      },
    }),
    { requestId: "req-signing-1", failureStage: "transaction_started" }
  );
  assert(signingFailure.status === 500, "Signing configuration failures should be server configuration errors");
  assert(
    signingFailure.payload.errorCode === "print_signing_configuration_invalid",
    "Signing configuration failures should be precise"
  );
  assert(
    signingFailure.payload.data.cryptoMetadata.errorCode === "ERR_OSSL_UNSUPPORTED",
    "Safe crypto metadata should preserve the OpenSSL error code"
  );

  const contextualFailure = describePrintJobCreateFailure(new Error("Unexpected downstream failure"), {
    requestId: "req-print-123",
    failureStage: "transaction_started",
    diagnostics: { batch: { present: true }, printerProfile: { found: true } },
  });
  assert(contextualFailure.payload.requestId === "req-print-123", "Failure payload should include requestId");
  assert(
    contextualFailure.payload.failureStage === "transaction_started",
    "Failure payload should include the server-side failure stage"
  );
  assert(
    contextualFailure.payload.data && contextualFailure.payload.data.diagnostics,
    "Failure payload should include safe diagnostics when available"
  );

  const repairedHeartbeatPrinter = pickSafeHeartbeatPrinterForProfile(
    {
      name: "ZDesigner ZT410-300dpi ZPL",
      nativePrinterId: "ZDesigner ZT410-300dpi ZPL",
      commandLanguage: "ZPL",
    },
    {
      selectedPrinterId: "Fax",
      selectedPrinterName: "Fax",
      printers: [
        {
          printerId: "Fax",
          printerName: "Fax",
          model: "Microsoft Shared Fax Driver",
          connection: "spooler",
          online: true,
          languages: [],
        },
        {
          printerId: "ZDesigner ZT410-300dpi ZPL",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "ZDesigner ZT410-300dpi ZPL",
          connection: "usb",
          online: true,
          languages: ["ZPL"],
        },
      ],
    }
  );
  assert(
    repairedHeartbeatPrinter?.printerId === "ZDesigner ZT410-300dpi ZPL",
    "Server-side mapping should repair stale Fax selection using trusted heartbeat inventory"
  );

  assert(
    hasExactTrustedSelectedPrinterMatch(
      {
        id: "00000000-0000-4000-8000-000000000402",
        name: "E2E Local Agent Printer",
        nativePrinterId: "e2e-local-printer",
        agentId: "e2e-agent",
        deviceFingerprint: "e2e-device-fingerprint",
        printerRegistrationId: "00000000-0000-4000-8000-000000000401",
      },
      {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        eligibleForPrinting: true,
        stale: false,
        registrationId: "00000000-0000-4000-8000-000000000401",
        agentId: "e2e-agent",
        deviceFingerprint: "e2e-device-fingerprint",
        printerId: "e2e-local-printer",
        printerName: "E2E Local Agent Printer",
        selectedPrinterId: "e2e-local-printer",
        selectedPrinterName: "E2E Local Agent Printer",
      }
    ),
    "Exact trusted E2E local-agent printer identity should not require Zebra naming"
  );

  assert(
    hasExactTrustedSelectedPrinterMatch(
      {
        name: "E2E Local Agent Printer",
        nativePrinterId: "e2e-local-printer",
        agentId: "e2e-agent",
        deviceFingerprint: "e2e-device-fingerprint",
        printerRegistrationId: "00000000-0000-4000-8000-000000000401",
      },
      {
        connected: true,
        trusted: false,
        compatibilityMode: true,
        eligibleForPrinting: true,
        stale: false,
        registrationId: "00000000-0000-4000-8000-000000000401",
        agentId: "e2e-agent",
        deviceFingerprint: "e2e-device-fingerprint",
        selectedPrinterId: "e2e-local-printer",
        selectedPrinterName: "E2E Local Agent Printer",
      }
    ),
    "Compatibility mode remains allowed when the exact profile identity is eligible and fresh"
  );

  const staleRegistrationAssessment = assessLocalAgentPrinterRelink(
    {
      id: "saved-printer-old",
      name: "ZDesigner ZT410-300dpi ZPL",
      connectionType: "LOCAL_AGENT",
      commandLanguage: "ZPL",
      nativePrinterId: "ZDesigner ZT410-300dpi ZPL",
      printerRegistrationId: "old-registration",
    },
    {
      connected: true,
      eligibleForPrinting: true,
      stale: false,
      registrationId: "new-registration",
      agentId: "agent-new",
      deviceFingerprint: "device-new",
      selectedPrinterId: "ZDesigner ZT410-300dpi ZPL",
      selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printers: [
        {
          printerId: "ZDesigner ZT410-300dpi ZPL",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "ZDesigner ZT410-300dpi ZPL",
          connection: "usb",
          online: true,
          languages: ["ZPL"],
        },
      ],
    }
  );
  assert(staleRegistrationAssessment.relinkRequired, "Connector reinstall registration mismatch should require relink");
  assert(staleRegistrationAssessment.eligible, "Same scoped native ZPL printer should be safe to relink");

  const unsafeNameOnlyAssessment = assessLocalAgentPrinterRelink(
    {
      id: "saved-printer-old",
      name: "ZDesigner ZT410-300dpi ZPL",
      connectionType: "LOCAL_AGENT",
      commandLanguage: "ZPL",
      nativePrinterId: "ZDesigner ZT410-300dpi ZPL",
      printerRegistrationId: "old-registration",
    },
    {
      connected: true,
      eligibleForPrinting: true,
      stale: false,
      registrationId: "new-registration",
      selectedPrinterId: "Fax",
      selectedPrinterName: "Fax",
      printers: [
        {
          printerId: "Fax",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "Microsoft Shared Fax Driver",
          connection: "spooler",
          online: true,
          languages: [],
        },
      ],
    }
  );
  assert(unsafeNameOnlyAssessment.relinkRequired, "Stale registration should still be detected");
  assert(!unsafeNameOnlyAssessment.eligible, "Virtual/non-label rows should not be relinked by display name alone");

  console.log("printer user-facing error tests passed");
};

run();
