import { createHash, randomUUID } from "crypto";
import {
  PrintPayloadType,
  Printer,
  PrinterConnectionType,
  PrinterDeliveryMode,
  PrinterLanguageKind,
} from "@prisma/client";

import { buildCanonicalQrLabel } from "../printing/canonicalLabel";
import { inspectIppJob, submitPdfToIppPrinter } from "../printing/ippClient";
import { normalizeLabelCalibration, renderPdfLabelBuffer } from "../printing/pdfLabel";
import { resolvePrinterLanguageRenderer } from "../printing/renderers";
import {
  PRINTER_TEST_QR_ID_PREFIX,
  buildScanUrl,
  randomNonce,
  signQrPayload,
} from "./qrTokenService";
import { sendRawPayloadToNetworkPrinter } from "./networkPrinterSocketService";
import { resolvePrinterConfirmationMode, type PrintConfirmationMode } from "./printConfirmationService";
import { resolvePayloadType, supportsNetworkDirectPayload } from "./printPayloadService";
import { getZebraTotalLabelCount, waitForZebraLabelConfirmation } from "./zebraPrinterStatusService";

const PRINTER_TEST_LABEL_TIMEOUT_MS = Math.max(
  15_000,
  Math.min(5 * 60_000, Number(process.env.PRINTER_TEST_LABEL_TIMEOUT_MS || 90_000) || 90_000)
);
const PRINTER_TEST_IPP_CONFIRM_POLL_MS = Math.max(
  500,
  Math.min(15_000, Number(process.env.PRINTER_TEST_IPP_CONFIRM_POLL_MS || 1500) || 1500)
);
const PRINTER_TEST_TOKEN_TTL_MS = Math.max(
  60 * 60_000,
  Math.min(14 * 24 * 60 * 60_000, Number(process.env.PRINTER_TEST_TOKEN_TTL_MS || 7 * 24 * 60 * 60_000) || 7 * 24 * 60 * 60_000)
);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256Hex = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

type RegisteredPrinterWithStatus = Printer & {
  profile?: {
    statusConfig?: unknown;
    activeLanguage?: PrinterLanguageKind | null;
  } | null;
};

export type PrinterTestLabelResult = {
  outcome: "confirmed";
  message: string;
  confirmationMode: PrintConfirmationMode | null;
  connectionType: PrinterConnectionType;
  deliveryMode: PrinterDeliveryMode;
  payloadType: PrintPayloadType | null;
  deviceJobRef: string | null;
  dispatchedAt: string;
  confirmedAt: string;
};

type GatewayPrinterTestClaim = {
  testJobId: string;
  connectionType: "NETWORK_DIRECT" | "NETWORK_IPP";
  code: string;
  scanUrl: string;
  previewLabel: string;
  printer: Record<string, unknown>;
  calibrationProfile: Record<string, unknown> | null;
  jobNumber: string;
  payloadType?: PrintPayloadType | null;
  payloadContent?: string | null;
  payloadHash?: string | null;
  commandLanguage?: string | null;
};

type GatewayPrinterTestJob = {
  id: string;
  printerId: string;
  connectionType: "NETWORK_DIRECT" | "NETWORK_IPP";
  createdAt: number;
  expiresAt: number;
  status: "PENDING" | "CLAIMED" | "ACKED" | "CONFIRMED" | "FAILED";
  claim: GatewayPrinterTestClaim;
  ackMetadata: Record<string, unknown> | null;
  timer: NodeJS.Timeout;
  resolve: (result: PrinterTestLabelResult) => void;
  reject: (error: Error) => void;
  promise: Promise<PrinterTestLabelResult>;
};

const gatewayPrinterTestJobsById = new Map<string, GatewayPrinterTestJob>();
const gatewayPrinterTestJobIdsByPrinterId = new Map<string, string>();

const resolveTestLanguageKind = (printer: RegisteredPrinterWithStatus): PrinterLanguageKind => {
  const normalized = String(printer.profile?.activeLanguage || printer.commandLanguage || "AUTO").trim().toUpperCase();
  if (normalized === "ZPL") return PrinterLanguageKind.ZPL;
  if (normalized === "EPL") return PrinterLanguageKind.EPL;
  if (normalized === "TSPL") return PrinterLanguageKind.TSPL;
  if (normalized === "DPL") return PrinterLanguageKind.DPL;
  if (normalized === "SBPL") return PrinterLanguageKind.SBPL;
  if (normalized === "HONEYWELL_DP") return PrinterLanguageKind.HONEYWELL_DP;
  if (normalized === "HONEYWELL_FINGERPRINT") return PrinterLanguageKind.HONEYWELL_FINGERPRINT;
  if (normalized === "IPL") return PrinterLanguageKind.IPL;
  if (normalized === "ZSIM") return PrinterLanguageKind.ZSIM;
  if (normalized === "PDF") return PrinterLanguageKind.PDF;
  return PrinterLanguageKind.AUTO;
};

const buildPrinterTestScanContext = (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}) => {
  const now = Date.now();
  const nonce = randomNonce();
  const payload = {
    qr_id: `${PRINTER_TEST_QR_ID_PREFIX}${params.printer.id}:${nonce}`,
    batch_id: null,
    licensee_id: params.printer.licenseeId || `printer-test-${params.printer.id}`,
    manufacturer_id: params.actorUserId,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + PRINTER_TEST_TOKEN_TTL_MS) / 1000),
    nonce,
  };
  const scanToken = signQrPayload(payload);
  return {
    code: `PRINTER-TEST-${nonce.slice(0, 8).toUpperCase()}`,
    previewLabel: "MSCQR PRINTER TEST LABEL",
    scanToken,
    scanUrl: buildScanUrl(scanToken),
  };
};

const buildDirectTestPayload = (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
  context?: ReturnType<typeof buildPrinterTestScanContext>;
}) => {
  const context = params.context || buildPrinterTestScanContext(params);
  const payloadType = resolvePayloadType(params.printer as any);
  const calibration = normalizeLabelCalibration((params.printer.calibrationProfile as Record<string, unknown> | null) || null);
  const document = buildCanonicalQrLabel({
    qrId: `${PRINTER_TEST_QR_ID_PREFIX}${params.printer.id}`,
    code: context.code,
    scanUrl: context.scanUrl,
    batchId: "printer-setup-test",
    batchName: "Printer Setup Test",
    printJobId: `printer-test-${params.printer.id}`,
    printItemId: null,
    reissueOfJobId: null,
    labelWidthMm: calibration.labelWidthMm,
    labelHeightMm: calibration.labelHeightMm,
    dpi: calibration.dpi,
  });
  const rendered = resolvePrinterLanguageRenderer(resolveTestLanguageKind(params.printer)).render(document, {
    dpi: calibration.dpi,
  });

  return {
    ...context,
    payloadType: rendered.payloadType || payloadType,
    payloadContent: rendered.payloadContent,
    payloadHash: sha256Hex(rendered.payloadContent),
  };
};

const waitForIppCompletion = async (params: {
  printer: RegisteredPrinterWithStatus;
  ippJobId: number;
  timeoutMs?: number;
}) => {
  const deadline = Date.now() + (params.timeoutMs || PRINTER_TEST_LABEL_TIMEOUT_MS);

  while (Date.now() < deadline) {
    const inspection = await inspectIppJob({
      profile: {
        host: params.printer.host,
        port: params.printer.port,
        resourcePath: params.printer.resourcePath,
        tlsEnabled: params.printer.tlsEnabled,
        printerUri: params.printer.printerUri,
      },
      jobId: params.ippJobId,
    });
    const reasons = inspection.jobStateReasons.map((value) => value.toLowerCase());

    if (inspection.jobState === 9) {
      if (
        reasons.some((reason) =>
          [
            "completed-with-errors",
            "job-completed-with-errors",
            "document-format-error",
            "processing-to-stop-point",
            "job-canceled-at-device",
            "job-canceled-by-operator",
            "job-canceled-by-user",
            "job-aborted-at-device",
          ].some((marker) => reason.includes(marker))
        )
      ) {
        throw new Error(
          `IPP printer reported a terminal completion error: ${inspection.jobStateReasons.join(", ") || "completed with errors"}`
        );
      }
      return inspection;
    }

    if (inspection.jobState === 7 || inspection.jobState === 8) {
      throw new Error(
        `IPP printer rejected the test label: ${
          inspection.jobStateMessage || inspection.jobStateReasons.join(", ") || `job-state ${inspection.jobState}`
        }`
      );
    }

    await sleep(PRINTER_TEST_IPP_CONFIRM_POLL_MS);
  }

  throw new Error("The printer accepted the test label but did not confirm completion before the setup timeout.");
};

const removeGatewayPrinterTestJob = (jobId: string) => {
  const job = gatewayPrinterTestJobsById.get(jobId);
  if (!job) return;
  clearTimeout(job.timer);
  gatewayPrinterTestJobsById.delete(jobId);
  if (gatewayPrinterTestJobIdsByPrinterId.get(job.printerId) === jobId) {
    gatewayPrinterTestJobIdsByPrinterId.delete(job.printerId);
  }
};

const getGatewayPrinterTestJob = (printerId: string) => {
  const jobId = gatewayPrinterTestJobIdsByPrinterId.get(printerId);
  if (!jobId) return null;
  const job = gatewayPrinterTestJobsById.get(jobId) || null;
  if (!job) {
    gatewayPrinterTestJobIdsByPrinterId.delete(printerId);
    return null;
  }
  if (Date.now() > job.expiresAt) {
    removeGatewayPrinterTestJob(job.id);
    job.reject(new Error("The site connector did not complete the printer test before the setup timeout."));
    return null;
  }
  return job;
};

const enqueueGatewayPrinterTestJob = (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}) => {
  const existing = getGatewayPrinterTestJob(params.printer.id);
  if (existing) {
    throw new Error("Another live test label is already running for this printer. Please wait for it to finish.");
  }

  const context = buildPrinterTestScanContext(params);
  const jobId = randomUUID();
  const expiresAt = Date.now() + PRINTER_TEST_LABEL_TIMEOUT_MS;
  const jobNumber = `SETUP-TEST-${context.code}`;
  const directPayload =
    params.printer.connectionType === PrinterConnectionType.NETWORK_DIRECT
      ? buildDirectTestPayload({ ...params, context })
      : null;

  let resolvePromise!: (result: PrinterTestLabelResult) => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<PrinterTestLabelResult>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  const claim: GatewayPrinterTestClaim =
    params.printer.connectionType === PrinterConnectionType.NETWORK_DIRECT
      ? {
          testJobId: jobId,
          connectionType: PrinterConnectionType.NETWORK_DIRECT,
          code: context.code,
          scanUrl: context.scanUrl,
          previewLabel: context.previewLabel,
          printer: {
            id: params.printer.id,
            name: params.printer.name,
            ipAddress: params.printer.ipAddress,
            port: params.printer.port,
          },
          calibrationProfile: (params.printer.calibrationProfile as Record<string, unknown> | null) || null,
          jobNumber,
          payloadType: directPayload?.payloadType || null,
          payloadContent: directPayload?.payloadContent || null,
          payloadHash: directPayload?.payloadHash || null,
          commandLanguage: params.printer.commandLanguage,
        }
      : {
          testJobId: jobId,
          connectionType: PrinterConnectionType.NETWORK_IPP,
          code: context.code,
          scanUrl: context.scanUrl,
          previewLabel: context.previewLabel,
          printer: {
            id: params.printer.id,
            name: params.printer.name,
            host: params.printer.host,
            port: params.printer.port,
            resourcePath: params.printer.resourcePath,
            tlsEnabled: params.printer.tlsEnabled,
            printerUri: params.printer.printerUri,
          },
          calibrationProfile: (params.printer.calibrationProfile as Record<string, unknown> | null) || null,
          jobNumber,
        };

  const timer = setTimeout(() => {
    removeGatewayPrinterTestJob(jobId);
    rejectPromise(new Error("The site connector did not claim and confirm the test label before the setup timeout."));
  }, PRINTER_TEST_LABEL_TIMEOUT_MS);

  const job: GatewayPrinterTestJob = {
    id: jobId,
    printerId: params.printer.id,
    connectionType: params.printer.connectionType as "NETWORK_DIRECT" | "NETWORK_IPP",
    createdAt: Date.now(),
    expiresAt,
    status: "PENDING",
    claim,
    ackMetadata: null,
    timer,
    resolve: resolvePromise,
    reject: rejectPromise,
    promise,
  };

  gatewayPrinterTestJobsById.set(jobId, job);
  gatewayPrinterTestJobIdsByPrinterId.set(params.printer.id, jobId);
  return job;
};

export const claimGatewayPrinterTestJob = (params: {
  printerId: string;
  connectionType: "NETWORK_DIRECT" | "NETWORK_IPP";
}) => {
  const job = getGatewayPrinterTestJob(params.printerId);
  if (!job || job.connectionType !== params.connectionType || job.status !== "PENDING") {
    return null;
  }
  job.status = "CLAIMED";
  return job.claim;
};

export const acknowledgeGatewayPrinterTestJob = (params: {
  printerId: string;
  testJobId: string;
  metadata?: Record<string, unknown> | null;
}) => {
  const job = getGatewayPrinterTestJob(params.printerId);
  if (!job || job.id !== params.testJobId) return false;
  job.status = "ACKED";
  job.ackMetadata = params.metadata || null;
  return true;
};

export const confirmGatewayPrinterTestJob = (params: {
  printerId: string;
  testJobId: string;
  payloadType?: PrintPayloadType | null;
  deviceJobRef?: string | null;
  confirmationMode?: PrintConfirmationMode | null;
  metadata?: Record<string, unknown> | null;
}) => {
  const job = getGatewayPrinterTestJob(params.printerId);
  if (!job || job.id !== params.testJobId) return false;

  job.status = "CONFIRMED";
  const now = new Date().toISOString();
  job.resolve({
    outcome: "confirmed",
    message:
      job.connectionType === PrinterConnectionType.NETWORK_IPP
        ? "The site connector printed the live IPP test label and the printer confirmed completion."
        : "The site connector printed the live label test and the printer confirmed completion.",
    confirmationMode: params.confirmationMode || null,
    connectionType: job.connectionType,
    deliveryMode: PrinterDeliveryMode.SITE_GATEWAY,
    payloadType: params.payloadType || null,
    deviceJobRef: params.deviceJobRef || null,
    dispatchedAt: now,
    confirmedAt: now,
  });
  removeGatewayPrinterTestJob(job.id);
  return true;
};

export const failGatewayPrinterTestJob = (params: {
  printerId: string;
  testJobId: string;
  reason: string;
}) => {
  const job = getGatewayPrinterTestJob(params.printerId);
  if (!job || job.id !== params.testJobId) return false;
  job.status = "FAILED";
  job.reject(new Error(params.reason || "The site connector reported a printer test failure."));
  removeGatewayPrinterTestJob(job.id);
  return true;
};

const dispatchGatewayPrinterTestLabel = async (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}) => {
  const job = enqueueGatewayPrinterTestJob(params);
  return job.promise;
};

const dispatchDirectIppTestLabel = async (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}): Promise<PrinterTestLabelResult> => {
  const confirmationMode = resolvePrinterConfirmationMode(params.printer);
  if (confirmationMode !== "IPP_JOB_STATE") {
    throw new Error("This IPP printer route does not expose strict terminal completion confirmation.");
  }

  const context = buildPrinterTestScanContext(params);
  const pdf = await renderPdfLabelBuffer({
    code: context.code,
    scanUrl: context.scanUrl,
    previewLabel: context.previewLabel,
    calibrationProfile: (params.printer.calibrationProfile as Record<string, unknown> | null) || null,
  });
  const dispatchedAt = new Date();
  const result = await submitPdfToIppPrinter({
    profile: {
      host: params.printer.host,
      port: params.printer.port,
      resourcePath: params.printer.resourcePath,
      tlsEnabled: params.printer.tlsEnabled,
      printerUri: params.printer.printerUri,
    },
    pdf,
    jobName: `MSCQR-SETUP-${context.code}`,
    requestingUserName: params.actorUserId,
  });
  if (!result.jobId) {
    throw new Error("The printer accepted the test label but did not return an IPP job id for completion confirmation.");
  }

  await waitForIppCompletion({
    printer: params.printer,
    ippJobId: result.jobId,
    timeoutMs: PRINTER_TEST_LABEL_TIMEOUT_MS,
  });

  return {
    outcome: "confirmed",
    message: "The live IPP test label printed successfully and the printer confirmed completion.",
    confirmationMode,
    connectionType: PrinterConnectionType.NETWORK_IPP,
    deliveryMode: PrinterDeliveryMode.DIRECT,
    payloadType: PrintPayloadType.PDF,
    deviceJobRef: String(result.jobId),
    dispatchedAt: dispatchedAt.toISOString(),
    confirmedAt: new Date().toISOString(),
  };
};

const dispatchDirectRawTestLabel = async (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}): Promise<PrinterTestLabelResult> => {
  const confirmationMode = resolvePrinterConfirmationMode(params.printer);
  if (confirmationMode !== "ZEBRA_ODOMETER") {
    throw new Error("This raw printer route is not yet certified for strict terminal completion confirmation.");
  }
  if (!params.printer.ipAddress || !params.printer.port) {
    throw new Error("The saved factory printer is missing its IP address or port.");
  }
  if (!supportsNetworkDirectPayload(params.printer as any)) {
    throw new Error("This printer route does not have a certified label-language payload for live testing.");
  }

  const payload = buildDirectTestPayload(params);
  const dispatchedAt = new Date();
  const startingLabelCount = await getZebraTotalLabelCount({
    ipAddress: params.printer.ipAddress,
    port: params.printer.port,
  });
  const socketResult = await sendRawPayloadToNetworkPrinter({
    ipAddress: params.printer.ipAddress,
    port: params.printer.port,
    payload: payload.payloadContent,
  });
  const deviceJobRef = `zebra-odometer:${startingLabelCount}`;

  await waitForZebraLabelConfirmation({
    ipAddress: params.printer.ipAddress,
    port: params.printer.port,
    startingLabelCount,
    expectedIncrement: 1,
    timeoutMs: PRINTER_TEST_LABEL_TIMEOUT_MS,
  });

  return {
    outcome: "confirmed",
    message: "The live raw-label test printed successfully and the printer confirmed completion.",
    confirmationMode,
    connectionType: PrinterConnectionType.NETWORK_DIRECT,
    deliveryMode: PrinterDeliveryMode.DIRECT,
    payloadType: payload.payloadType,
    deviceJobRef: deviceJobRef || String(socketResult.bytesWritten || ""),
    dispatchedAt: dispatchedAt.toISOString(),
    confirmedAt: new Date().toISOString(),
  };
};

export const printTestLabelForRegisteredPrinter = async (params: {
  printer: RegisteredPrinterWithStatus;
  actorUserId: string;
}) => {
  if (params.printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
    throw new Error("Local workstation printers do not use this managed test-label path.");
  }

  if (params.printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
    return dispatchGatewayPrinterTestLabel(params);
  }

  if (params.printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    return dispatchDirectIppTestLabel(params);
  }

  if (params.printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    return dispatchDirectRawTestLabel(params);
  }

  throw new Error("Unsupported printer route for live test labels.");
};
