import { BatchLifecycleState, Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import {
  readPrintingProjection,
  releasePrintingBatch,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";

type ReleaseCheckFailure = { code: string; message: string };
type ReleaseApprovalPolicy = { required: boolean; reason: string | null; threshold: number | null };
type Boundary = { capability: string; requestId: string };

export type BatchReleaseReadiness = {
  releasable: boolean;
  batchId: string;
  lifecycleState: BatchLifecycleState;
  printJobId: string | null;
  sampleScanPolicy: {
    mode: string;
    required: number;
    passed: number;
    satisfied: boolean;
  } | null;
  failures: ReleaseCheckFailure[];
};

const parseEnabled = (value: unknown) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const configuredDualApprovalThreshold = () => {
  const raw = Number(String(process.env.BATCH_RELEASE_DUAL_APPROVAL_QUANTITY_THRESHOLD || "").trim());
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : null;
};

export const evaluateBatchReleaseApprovalPolicy = (batch: { totalCodes?: number | null }): ReleaseApprovalPolicy => {
  const threshold = configuredDualApprovalThreshold();
  if (!parseEnabled(process.env.BATCH_RELEASE_DUAL_APPROVAL_ENABLED) || !threshold) {
    return { required: false, reason: null, threshold };
  }
  return Number(batch.totalCodes || 0) >= threshold
    ? { required: true, reason: "quantity_threshold", threshold }
    : { required: false, reason: null, threshold };
};

const releaseProjection = async (batchId: string, boundary: Boundary) =>
  readPrintingProjection({
    capability: boundary.capability,
    requestId: boundary.requestId,
    operation: "RELEASE",
    subjectId: batchId,
  });

const projectReadiness = (projection: any): BatchReleaseReadiness => {
  const batch = projection.batch;
  const job = projection.latestJob || null;
  const required = Number(projection.sampleRequired || 1);
  const passed = Number(projection.sampleCount || 0);
  const failures: ReleaseCheckFailure[] = [];
  if (batch.lifecycleState === "RELEASED" || batch.releasedAt) failures.push({ code: "already_released", message: "Batch is already released." });
  if (Number(projection.qrCount || 0) === 0) failures.push({ code: "codes_missing", message: "Batch has no generated QR labels." });
  if (!job) failures.push({ code: "print_job_missing", message: "Batch has no print job." });
  else if (job.status !== "CONFIRMED" || !job.confirmedAt) failures.push({ code: "physical_print_not_confirmed", message: "Labels have not been physically confirmed." });
  if (batch.lifecycleState !== "SAMPLE_VERIFIED" || passed < required) {
    failures.push({ code: "sample_scan_policy_incomplete", message: `Sample scan proof is incomplete: ${passed}/${required} complete.` });
  }
  return {
    releasable: failures.length === 0,
    batchId: batch.id,
    lifecycleState: batch.lifecycleState,
    printJobId: job?.id || null,
    sampleScanPolicy: job ? { mode: "DATABASE_POLICY", required, passed, satisfied: passed >= required } : null,
    failures,
  };
};

export const evaluateBatchReleaseReadiness = async (params: {
  batchId: string;
  boundary: Boundary;
}) => projectReadiness(await releaseProjection(params.batchId, params.boundary));

export const getBatchReleaseApprovalContext = async (params: {
  batchId: string;
  boundary: Boundary;
}) => {
  const projection = await releaseProjection(params.batchId, params.boundary);
  return {
    batch: projection.batch,
    readiness: projectReadiness(projection),
    approvalPolicy: evaluateBatchReleaseApprovalPolicy(projection.batch),
  };
};

export const releaseBatchForSupplyChain = async (params: {
  batchId: string;
  boundary: Boundary;
  approvalSatisfied?: boolean;
}) => {
  if (params.approvalSatisfied === false) {
    throw Object.assign(new Error("A second authorized checker must approve this release."), {
      statusCode: 409,
      code: "CHECKER_REQUIRED",
    });
  }
  const projection = await releaseProjection(params.batchId, params.boundary);
  const readiness = projectReadiness(projection);
  if (!readiness.releasable) {
    throw Object.assign(new Error(readiness.failures[0]?.message || "Batch is not ready for release."), {
      statusCode: 409,
      readiness,
    });
  }
  const batch = await releasePrintingBatch({
    capability: params.boundary.capability,
    requestId: params.boundary.requestId,
    batchId: params.batchId,
    decision: "APPROVE",
  });
  return { batch, readiness, approvalPolicy: evaluateBatchReleaseApprovalPolicy(projection.batch) };
};

export const requestOrApproveBatchRelease = async (params: {
  batchId: string;
  boundary: Boundary;
  reason?: string | null;
}) => {
  const projection = await releaseProjection(params.batchId, params.boundary);
  const readiness = projectReadiness(projection);
  if (!readiness.releasable) {
    throw Object.assign(new Error(readiness.failures[0]?.message || "Batch is not ready for release."), {
      statusCode: 409,
      readiness,
    });
  }
  const batch = await releasePrintingBatch({
    capability: params.boundary.capability,
    requestId: params.boundary.requestId,
    batchId: params.batchId,
    decision: "REQUEST",
    reason: params.reason,
  });
  return { batch, readiness, approvalPolicy: evaluateBatchReleaseApprovalPolicy(projection.batch) };
};

// Public-identity incident guards remain outside the printing state machine.
export const assertQrPublicIdentityMutable = async (params: {
  qrCodeId: string;
  tx?: Prisma.TransactionClient;
}) => {
  const tx = params.tx || prisma;
  const qr = await tx.qRCode.findUnique({
    where: { id: params.qrCodeId },
    select: {
      status: true,
      printedAt: true,
      scannedAt: true,
      scanCount: true,
      redeemedAt: true,
      printJobId: true,
      tokenIssuedAt: true,
      customerVerifiableAt: true,
      signedFirstSeenAt: true,
      lastSignedVerificationAt: true,
      batch: { select: { lifecycleState: true, releasedAt: true } },
    },
  });
  if (!qr) throw new Error("QR code not found.");
  if (
    qr.printedAt || qr.scannedAt || Number(qr.scanCount || 0) > 0 || qr.redeemedAt ||
    qr.printJobId || qr.tokenIssuedAt || qr.customerVerifiableAt || qr.signedFirstSeenAt ||
    qr.lastSignedVerificationAt || qr.batch?.releasedAt || qr.batch?.lifecycleState === BatchLifecycleState.RELEASED ||
    ([QRStatus.ACTIVATED, QRStatus.PRINTED, QRStatus.REDEEMED, QRStatus.SCANNED, QRStatus.BLOCKED] as QRStatus[]).includes(qr.status)
  ) {
    throw Object.assign(new Error("QR public identity is immutable after print, scan, release, or external exposure."), { statusCode: 409 });
  }
};
