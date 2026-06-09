import {
  BatchLifecycleState,
  Prisma,
  PrintJobStatus,
  PrintPipelineState,
  PrintItemState,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import {
  assertBatchTransitionAllowedFromDb,
  BatchStateTransitionError,
} from "./batchStateMachineService";
import { evaluateSampleScanPolicy, type SampleScanPolicyResult } from "./sampleScanPolicyService";

type BatchReleaseClient = Pick<
  typeof prisma,
  "batch" | "qRCode" | "printAuditEvent" | "printItem" | "printJob" | "auditLog" | "sensitiveActionApproval"
>;

const SOCKET_ACK_STATES = new Set<PrintPipelineState>([
  PrintPipelineState.SENT_TO_PRINTER,
  PrintPipelineState.PRINTER_ACKNOWLEDGED,
  PrintPipelineState.PRINT_CONFIRMED,
  PrintPipelineState.LOCKED,
]);

const MUTATION_LOCK_STATES = [
  PrintItemState.RESERVED,
  PrintItemState.ISSUED,
  PrintItemState.AGENT_ACKED,
  PrintItemState.FROZEN,
  PrintItemState.FAILED,
];

type ReleaseCheckFailure = {
  code: string;
  message: string;
};

type ReleaseApprovalPolicy = {
  required: boolean;
  reason: string | null;
  threshold: number | null;
};

export type BatchReleaseReadiness = {
  releasable: boolean;
  batchId: string;
  lifecycleState: BatchLifecycleState;
  printJobId: string | null;
  sampleScanPolicy: SampleScanPolicyResult | null;
  failures: ReleaseCheckFailure[];
};

const safeFailure = (code: string, message: string): ReleaseCheckFailure => ({ code, message });

const parseEnabled = (value: unknown) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const configuredDualApprovalThreshold = () => {
  const raw = Number(String(process.env.BATCH_RELEASE_DUAL_APPROVAL_QUANTITY_THRESHOLD || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return null;
  return Math.floor(raw);
};

export const evaluateBatchReleaseApprovalPolicy = (batch: { totalCodes?: number | null }): ReleaseApprovalPolicy => {
  if (!parseEnabled(process.env.BATCH_RELEASE_DUAL_APPROVAL_ENABLED)) {
    return { required: false, reason: null, threshold: null };
  }

  const threshold = configuredDualApprovalThreshold();
  if (!threshold) return { required: false, reason: null, threshold: null };

  const quantity = Math.max(0, Math.floor(Number(batch.totalCodes || 0)));
  if (quantity >= threshold) {
    return {
      required: true,
      reason: "quantity_threshold",
      threshold,
    };
  }

  return { required: false, reason: null, threshold };
};

const latestRelevantPrintJob = async (tx: BatchReleaseClient, batchId: string) =>
  tx.printJob.findFirst({
    where: { batchId },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    include: {
      printSession: {
        select: {
          id: true,
          status: true,
          totalItems: true,
          confirmedItems: true,
          failedReason: true,
        },
      },
    },
  });

export const evaluateBatchReleaseReadiness = async (params: {
  batchId: string;
  actorUserId?: string | null;
  tx?: BatchReleaseClient;
}): Promise<BatchReleaseReadiness> => {
  const tx: BatchReleaseClient = params.tx || prisma;
  const batch = await tx.batch.findUnique({
    where: { id: params.batchId },
    select: {
      id: true,
      lifecycleState: true,
      releasedAt: true,
      manufacturerId: true,
      totalCodes: true,
      sampleScanPolicy: true,
    },
  });
  if (!batch) {
    return {
      releasable: false,
      batchId: params.batchId,
      lifecycleState: BatchLifecycleState.DRAFT,
      printJobId: null,
      sampleScanPolicy: null,
      failures: [safeFailure("batch_not_found", "Batch not found.")],
    };
  }

  const failures: ReleaseCheckFailure[] = [];
  if (batch.lifecycleState === BatchLifecycleState.RELEASED || batch.releasedAt) {
    failures.push(safeFailure("already_released", "Batch is already released."));
  }

  const [qrCount, missingPublicCodes, unsafeGeneratedCodes, lockedItems, latestJob] = await Promise.all([
    tx.qRCode.count({ where: { batchId: batch.id } }),
    tx.qRCode.count({ where: { batchId: batch.id, code: "" } }),
    tx.qRCode.count({
      where: {
        batchId: batch.id,
        code: { not: { startsWith: "c_" } },
        issuanceMode: { not: "LEGACY_UNSPECIFIED" },
      },
    }),
    tx.printItem.count({
      where: {
        qrCode: { batchId: batch.id },
        state: { in: MUTATION_LOCK_STATES },
      },
    }),
    latestRelevantPrintJob(tx, batch.id),
  ]);

  if (qrCount <= 0) failures.push(safeFailure("codes_missing", "Batch has no generated QR labels."));
  if (missingPublicCodes > 0) failures.push(safeFailure("public_code_missing", "One or more labels are missing a public verification code."));
  if (unsafeGeneratedCodes > 0) failures.push(safeFailure("unsafe_public_code_shape", "One or more newly issued labels do not use governed public code format."));
  if (lockedItems > 0) failures.push(safeFailure("qr_mutation_locked", "Some labels are still locked by an unfinished print workflow."));

  let sampleScanPolicy: SampleScanPolicyResult | null = null;
  if (!latestJob) {
    failures.push(safeFailure("print_job_missing", "Batch has no print job."));
  } else {
    if (latestJob.status === PrintJobStatus.FAILED || latestJob.status === PrintJobStatus.CANCELLED) {
      failures.push(safeFailure("latest_print_job_failed", "Latest print job is not releasable."));
    }
    if (!latestJob.sentAt && !SOCKET_ACK_STATES.has(latestJob.pipelineState)) {
      failures.push(safeFailure("print_not_acknowledged", "Print job has not been acknowledged as sent to printer."));
    }
    if (latestJob.status !== PrintJobStatus.CONFIRMED || !latestJob.confirmedAt) {
      failures.push(safeFailure("physical_print_not_confirmed", "Labels have not been physically confirmed by an operator."));
    }
    if (latestJob.printSession?.status === "FAILED") {
      failures.push(safeFailure("print_session_failed", "Print session has a failed state that must be resolved before release."));
    }

    sampleScanPolicy = await evaluateSampleScanPolicy({
      batchId: batch.id,
      printJobId: latestJob.id,
      policy: batch.sampleScanPolicy,
      quantity: latestJob.itemCount || latestJob.quantity || batch.totalCodes || qrCount,
      tx,
    });
    if (!sampleScanPolicy.satisfied) {
      failures.push(
        safeFailure(
          "sample_scan_policy_incomplete",
          `Sample scan proof is incomplete: ${sampleScanPolicy.passed}/${sampleScanPolicy.required} complete.`
        )
      );
    }
  }

  return {
    releasable: failures.length === 0,
    batchId: batch.id,
    lifecycleState: batch.lifecycleState,
    printJobId: latestJob?.id || null,
    sampleScanPolicy,
    failures,
  };
};

export const releaseBatchForSupplyChain = async (params: {
  batchId: string;
  actorUserId: string;
  actorManufacturerId?: string | null;
  approvalSatisfied?: boolean;
  approvalId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}) =>
  prisma.$transaction(async (tx) => {
    const batch = await tx.batch.findFirst({
      where: {
        id: params.batchId,
        ...(params.actorManufacturerId ? { manufacturerId: params.actorManufacturerId } : {}),
      },
      select: {
        id: true,
        licenseeId: true,
        manufacturerId: true,
        lifecycleState: true,
        totalCodes: true,
        releasedAt: true,
        releasedByUserId: true,
      },
    });
    if (!batch) {
      throw Object.assign(new Error("Batch not found."), { statusCode: 404 });
    }
    if (batch.lifecycleState === BatchLifecycleState.RELEASED || batch.releasedAt) {
      return {
        batch: {
          id: batch.id,
          lifecycleState: BatchLifecycleState.RELEASED,
          releasedAt: batch.releasedAt,
          releasedByUserId: batch.releasedByUserId,
        },
        readiness: {
          releasable: true,
          batchId: batch.id,
          lifecycleState: BatchLifecycleState.RELEASED,
          printJobId: null,
          sampleScanPolicy: null,
          failures: [],
        } satisfies BatchReleaseReadiness,
        approvalPolicy: evaluateBatchReleaseApprovalPolicy(batch),
        alreadyReleased: true,
      };
    }

    const readiness = await evaluateBatchReleaseReadiness({ batchId: batch.id, actorUserId: params.actorUserId, tx });
    if (!readiness.releasable) {
      await tx.printAuditEvent.create({
        data: {
          batchId: batch.id,
          printJobId: readiness.printJobId,
          actorId: params.actorUserId,
          eventType: "batch_release_blocked",
          metadata: {
            failures: readiness.failures,
            sampleScanPolicy: readiness.sampleScanPolicy,
          } as Prisma.InputJsonValue,
        },
      });
      await tx.auditLog.create({
        data: {
          userId: params.actorUserId,
          licenseeId: batch.licenseeId,
          action: "BATCH_RELEASE_BLOCKED",
          entityType: "Batch",
          entityId: batch.id,
          details: {
            failures: readiness.failures,
            sampleScanPolicy: readiness.sampleScanPolicy,
          } as Prisma.InputJsonValue,
          ipAddress: params.ipAddress || undefined,
          userAgent: params.userAgent || undefined,
        },
      });
      throw Object.assign(new Error(readiness.failures[0]?.message || "Batch is not ready for release."), {
        statusCode: 409,
        readiness,
      });
    }

    const approvalPolicy = evaluateBatchReleaseApprovalPolicy(batch);
    let approvalSatisfied = params.approvalSatisfied || !approvalPolicy.required;
    if (approvalPolicy.required) {
      if (!params.approvalId) {
        approvalSatisfied = false;
      } else {
        const approval = await tx.sensitiveActionApproval.findUnique({
          where: { id: params.approvalId },
          select: {
            id: true,
            actionKey: true,
            entityType: true,
            entityId: true,
            status: true,
            reviewedByUserId: true,
          },
        });
        approvalSatisfied = Boolean(
          approval &&
            approval.actionKey === "BATCH_RELEASE" &&
            approval.entityType === "Batch" &&
            approval.entityId === batch.id &&
            approval.status === "APPROVED" &&
            approval.reviewedByUserId === params.actorUserId
        );
      }
    }
    await assertBatchTransitionAllowedFromDb({
      batchId: batch.id,
      toStatus: "RELEASED",
      actor: { userId: params.actorUserId },
      printJobId: readiness.printJobId,
      approvalRequired: approvalPolicy.required,
      approvalSatisfied,
      tx,
    }).catch(async (error) => {
      if (error instanceof BatchStateTransitionError) {
        await tx.printAuditEvent.create({
          data: {
            batchId: batch.id,
            printJobId: readiness.printJobId,
            actorId: params.actorUserId,
            eventType: "batch_release_blocked",
            metadata: {
              code: error.code,
              message: error.message,
              approvalPolicy,
              approvalId: params.approvalId || null,
            } as Prisma.InputJsonValue,
          },
        });
      }
      throw error;
    });

    const now = new Date();
    const released = await tx.batch.update({
      where: { id: batch.id },
      data: {
        lifecycleState: BatchLifecycleState.RELEASED,
        releasedAt: now,
        releasedByUserId: params.actorUserId,
      },
      select: {
        id: true,
        lifecycleState: true,
        releasedAt: true,
        releasedByUserId: true,
      },
    });

    await tx.printAuditEvent.create({
      data: {
        batchId: batch.id,
        printJobId: readiness.printJobId,
        actorId: params.actorUserId,
        eventType: "batch_released",
        metadata: {
          sampleScanPolicy: readiness.sampleScanPolicy,
          releaseBoundary: "supply_chain",
          approvalId: params.approvalId || null,
        } as Prisma.InputJsonValue,
      },
    });
    await tx.auditLog.create({
      data: {
        userId: params.actorUserId,
        licenseeId: batch.licenseeId,
        action: "BATCH_RELEASED",
        entityType: "Batch",
        entityId: batch.id,
        details: {
          printJobId: readiness.printJobId,
          sampleScanPolicy: readiness.sampleScanPolicy,
          releaseBoundary: "supply_chain",
          approvalId: params.approvalId || null,
        } as Prisma.InputJsonValue,
        ipAddress: params.ipAddress || undefined,
        userAgent: params.userAgent || undefined,
      },
    });

    return {
      batch: released,
      readiness,
      approvalPolicy,
    };
  });

export const getBatchReleaseApprovalContext = async (params: {
  batchId: string;
  actorUserId: string;
  actorManufacturerId?: string | null;
}) =>
  prisma.$transaction(async (tx) => {
    const batch = await tx.batch.findFirst({
      where: {
        id: params.batchId,
        ...(params.actorManufacturerId ? { manufacturerId: params.actorManufacturerId } : {}),
      },
      select: {
        id: true,
        licenseeId: true,
        manufacturerId: true,
        totalCodes: true,
      },
    });
    if (!batch) {
      throw Object.assign(new Error("Batch not found."), { statusCode: 404 });
    }

    const readiness = await evaluateBatchReleaseReadiness({ batchId: batch.id, actorUserId: params.actorUserId, tx });
    return {
      batch,
      readiness,
      approvalPolicy: evaluateBatchReleaseApprovalPolicy(batch),
    };
  });

export const assertQrPublicIdentityMutable = async (params: {
  qrCodeId: string;
  tx?: Prisma.TransactionClient;
}) => {
  const tx = params.tx || prisma;
  const qr = await tx.qRCode.findUnique({
    where: { id: params.qrCodeId },
    select: {
      id: true,
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
      batch: {
        select: {
          lifecycleState: true,
          releasedAt: true,
        },
      },
    },
  });
  if (!qr) throw new Error("QR code not found.");

  const unsafe =
    qr.printedAt ||
    qr.scannedAt ||
    Number(qr.scanCount || 0) > 0 ||
    qr.redeemedAt ||
    qr.printJobId ||
    qr.tokenIssuedAt ||
    qr.customerVerifiableAt ||
    qr.signedFirstSeenAt ||
    qr.lastSignedVerificationAt ||
    qr.batch?.releasedAt ||
    qr.batch?.lifecycleState === BatchLifecycleState.RELEASED ||
    ([QRStatus.ACTIVATED, QRStatus.PRINTED, QRStatus.REDEEMED, QRStatus.SCANNED, QRStatus.BLOCKED] as QRStatus[]).includes(qr.status);

  if (unsafe) {
    throw Object.assign(new Error("QR public identity is immutable after print, scan, release, or external exposure."), {
      statusCode: 409,
    });
  }
};
