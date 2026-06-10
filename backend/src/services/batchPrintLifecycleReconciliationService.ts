import { BatchLifecycleState, PrintJobStatus, PrintSessionStatus, QRStatus, Prisma } from "@prisma/client";

import prisma from "../config/database";
import { countReservableQrCodesForPrint } from "./printReservationService";

type ReconciliationClient = Pick<
  typeof prisma,
  "batch" | "qRCode" | "printJob" | "printSession" | "printAuditEvent" | "auditLog" | "$queryRaw"
>;

export type BatchPrintReadiness = {
  printable: boolean;
  batchId: string;
  currentLifecycleState: BatchLifecycleState;
  requiredPreviousStep: string | null;
  userMessage: string;
  recoveryAction: string;
  canRetry: boolean;
  canRepairAutomatically: boolean;
  reasonCode: string;
  availableToPrint: number;
};

export type BatchPrintLifecycleEvidence = {
  printedAt: Date | null;
  printedQrCount: number;
  confirmedPrintJobCount: number;
  completedPrintSessionCount: number;
  allocatedQrCount: number;
  latestConfirmedPrintJobId: string | null;
};

export type BatchPrintLifecycleReconciliationResult = {
  batchId: string;
  beforeState: BatchLifecycleState;
  afterState: BatchLifecycleState;
  mutated: boolean;
  targetState: BatchLifecycleState | null;
  evidence: BatchPrintLifecycleEvidence;
  readiness: BatchPrintReadiness;
};

const PRINTABLE_STATES = new Set<BatchLifecycleState>([
  BatchLifecycleState.CODES_GENERATED,
  BatchLifecycleState.PRINT_ACKNOWLEDGED,
  BatchLifecycleState.PRINT_CONFIRMED,
  BatchLifecycleState.SAMPLE_VERIFIED,
]);

const PRINT_EVIDENCE_QR_STATUSES: QRStatus[] = [QRStatus.PRINTED, QRStatus.REDEEMED, QRStatus.SCANNED];

const terminalBlockedMessage = (state: BatchLifecycleState) =>
  state === BatchLifecycleState.RELEASED
    ? "This batch has already been released and is locked for supply-chain use."
    : "This batch is not available for printing.";

export const buildBatchPrintReadiness = (params: {
  batchId: string;
  lifecycleState?: BatchLifecycleState | null;
  releasedAt?: Date | string | null;
  availableToPrint?: number | null;
  canRepairAutomatically?: boolean;
  repairTargetState?: BatchLifecycleState | null;
}): BatchPrintReadiness => {
  const currentLifecycleState = params.lifecycleState || BatchLifecycleState.DRAFT;
  const availableToPrint = Math.max(0, Number(params.availableToPrint || 0));
  const canRepairAutomatically = Boolean(params.canRepairAutomatically);

  if (currentLifecycleState === BatchLifecycleState.RELEASED || params.releasedAt) {
    return {
      printable: false,
      batchId: params.batchId,
      currentLifecycleState,
      requiredPreviousStep: null,
      userMessage: terminalBlockedMessage(BatchLifecycleState.RELEASED),
      recoveryAction: "open_reissue_or_support",
      canRetry: false,
      canRepairAutomatically: false,
      reasonCode: "batch_released",
      availableToPrint,
    };
  }

  if (currentLifecycleState === BatchLifecycleState.FAILED || currentLifecycleState === BatchLifecycleState.VOIDED) {
    return {
      printable: false,
      batchId: params.batchId,
      currentLifecycleState,
      requiredPreviousStep: "Resolve the blocked batch state before printing.",
      userMessage: terminalBlockedMessage(currentLifecycleState),
      recoveryAction: "contact_support",
      canRetry: false,
      canRepairAutomatically: false,
      reasonCode: "batch_terminal",
      availableToPrint,
    };
  }

  const lifecyclePrintable = PRINTABLE_STATES.has(currentLifecycleState) || canRepairAutomatically;
  if (!lifecyclePrintable) {
    return {
      printable: false,
      batchId: params.batchId,
      currentLifecycleState,
      requiredPreviousStep: "Allocate QR labels to this manufacturer before printing.",
      userMessage: "This batch needs to be allocated before printing.",
      recoveryAction: "complete_previous_batch_step",
      canRetry: false,
      canRepairAutomatically: false,
      reasonCode: "batch_lifecycle_blocked",
      availableToPrint,
    };
  }

  if (availableToPrint <= 0) {
    return {
      printable: false,
      batchId: params.batchId,
      currentLifecycleState,
      requiredPreviousStep: "Add or recover allocated QR labels before printing.",
      userMessage: "There are no labels ready to print in this batch.",
      recoveryAction: "refresh_batch_inventory",
      canRetry: true,
      canRepairAutomatically,
      reasonCode: "no_printable_inventory",
      availableToPrint,
    };
  }

  return {
    printable: true,
    batchId: params.batchId,
    currentLifecycleState,
    requiredPreviousStep: null,
    userMessage: canRepairAutomatically
      ? "Batch state can be repaired from existing print or allocation evidence before printing."
      : "Batch is ready to print.",
    recoveryAction: canRepairAutomatically ? "auto_repair_then_retry" : "start_print_run",
    canRetry: true,
    canRepairAutomatically,
    reasonCode: canRepairAutomatically ? "batch_lifecycle_repair_available" : "batch_printable",
    availableToPrint,
  };
};

export const buildBatchPrintReadinessFromSummary = (params: {
  batchId: string;
  lifecycleState?: BatchLifecycleState | null;
  releasedAt?: Date | string | null;
  availableToPrint?: number | null;
  printedAt?: Date | string | null;
  printedCodes?: number | null;
  allocatedCodes?: number | null;
  manufacturerId?: string | null;
  parentBatchId?: string | null;
  rootBatchId?: string | null;
}) => {
  const lifecycleState = params.lifecycleState || BatchLifecycleState.DRAFT;
  const printedEvidence = Boolean(params.printedAt) || Number(params.printedCodes || 0) > 0;
  const allocationEvidence =
    Boolean(params.manufacturerId) &&
    Boolean(params.parentBatchId || params.rootBatchId) &&
    Number(params.allocatedCodes || 0) > 0;
  const repairTargetState = printedEvidence
    ? BatchLifecycleState.PRINT_CONFIRMED
    : allocationEvidence
      ? BatchLifecycleState.CODES_GENERATED
      : null;

  return buildBatchPrintReadiness({
    batchId: params.batchId,
    lifecycleState,
    releasedAt: params.releasedAt || null,
    availableToPrint: params.availableToPrint || 0,
    canRepairAutomatically: lifecycleState === BatchLifecycleState.DRAFT && Boolean(repairTargetState),
    repairTargetState,
  });
};

const loadEvidence = async (client: ReconciliationClient, batchId: string): Promise<BatchPrintLifecycleEvidence> => {
  const [batch, printedQrCount, confirmedPrintJobCount, completedPrintSessionCount, latestConfirmedPrintJob, allocatedQrCount] =
    await Promise.all([
      client.batch.findUnique({ where: { id: batchId }, select: { printedAt: true } }),
      client.qRCode.count({ where: { batchId, status: { in: PRINT_EVIDENCE_QR_STATUSES } } }),
      client.printJob.count({
        where: {
          batchId,
          OR: [{ status: PrintJobStatus.CONFIRMED }, { confirmedAt: { not: null } }, { completedAt: { not: null } }],
        },
      }),
      client.printSession.count({
        where: {
          batchId,
          status: PrintSessionStatus.COMPLETED,
          confirmedItems: { gt: 0 },
        },
      }),
      client.printJob.findFirst({
        where: {
          batchId,
          OR: [{ status: PrintJobStatus.CONFIRMED }, { confirmedAt: { not: null } }, { completedAt: { not: null } }],
        },
        orderBy: [{ confirmedAt: "desc" }, { completedAt: "desc" }, { createdAt: "desc" }, { id: "desc" }],
        select: { id: true },
      }),
      client.qRCode.count({ where: { batchId, status: QRStatus.ALLOCATED, printJobId: null } }),
    ]);

  return {
    printedAt: batch?.printedAt || null,
    printedQrCount,
    confirmedPrintJobCount,
    completedPrintSessionCount,
    allocatedQrCount,
    latestConfirmedPrintJobId: latestConfirmedPrintJob?.id || null,
  };
};

const resolveRepairTargetState = (params: {
  batch: {
    lifecycleState: BatchLifecycleState;
    manufacturerId: string | null;
    parentBatchId: string | null;
    rootBatchId: string | null;
  };
  evidence: BatchPrintLifecycleEvidence;
}) => {
  if (
    params.evidence.printedAt ||
    params.evidence.printedQrCount > 0 ||
    params.evidence.confirmedPrintJobCount > 0 ||
    params.evidence.completedPrintSessionCount > 0
  ) {
    if (
      params.batch.lifecycleState === BatchLifecycleState.RELEASED ||
      params.batch.lifecycleState === BatchLifecycleState.FAILED ||
      params.batch.lifecycleState === BatchLifecycleState.VOIDED ||
      params.batch.lifecycleState === BatchLifecycleState.PRINT_CONFIRMED ||
      params.batch.lifecycleState === BatchLifecycleState.SAMPLE_VERIFIED
    ) {
      return null;
    }
    return BatchLifecycleState.PRINT_CONFIRMED;
  }
  if (params.batch.lifecycleState !== BatchLifecycleState.DRAFT) return null;
  if (
    params.batch.manufacturerId &&
    (params.batch.parentBatchId || params.batch.rootBatchId) &&
    params.evidence.allocatedQrCount > 0
  ) {
    return BatchLifecycleState.CODES_GENERATED;
  }
  return null;
};

export const reconcileBatchPrintLifecycle = async (params: {
  batchId: string;
  actorUserId?: string | null;
  apply?: boolean;
  reason?: string;
  tx?: ReconciliationClient;
}): Promise<BatchPrintLifecycleReconciliationResult> => {
  const client = params.tx || prisma;
  const batch = await client.batch.findUnique({
    where: { id: params.batchId },
    select: {
      id: true,
      licenseeId: true,
      manufacturerId: true,
      parentBatchId: true,
      rootBatchId: true,
      lifecycleState: true,
      releasedAt: true,
    },
  });
  if (!batch) {
    throw Object.assign(new Error("Batch not found."), { statusCode: 404 });
  }

  const [evidence, availableToPrint] = await Promise.all([
    loadEvidence(client, batch.id),
    countReservableQrCodesForPrint(client as Prisma.TransactionClient, { batchId: batch.id }).catch(() => 0),
  ]);
  const targetState = resolveRepairTargetState({ batch, evidence });
  const canRepairAutomatically = Boolean(targetState && batch.lifecycleState === BatchLifecycleState.DRAFT);
  let afterState = batch.lifecycleState;
  let mutated = false;

  if (params.apply && targetState) {
    const updated = await client.batch.updateMany({
      where: {
        id: batch.id,
        lifecycleState:
          targetState === BatchLifecycleState.PRINT_CONFIRMED
            ? { in: [BatchLifecycleState.DRAFT, BatchLifecycleState.CODES_GENERATED, BatchLifecycleState.PRINT_ACKNOWLEDGED] }
            : BatchLifecycleState.DRAFT,
        releasedAt: null,
      },
      data: {
        lifecycleState: targetState,
        ...(targetState === BatchLifecycleState.PRINT_CONFIRMED ? { printedAt: evidence.printedAt || new Date() } : {}),
      },
    });
    mutated = updated.count > 0;
    afterState = mutated ? targetState : batch.lifecycleState;

    if (mutated) {
      const metadata = {
        reason: params.reason || "print_lifecycle_reconciliation",
        previousLifecycleState: batch.lifecycleState,
        nextLifecycleState: targetState,
        evidence,
      } as Prisma.InputJsonValue;
      await client.printAuditEvent.create({
        data: {
          batchId: batch.id,
          printJobId: evidence.latestConfirmedPrintJobId,
          actorId: params.actorUserId || null,
          eventType: "batch_lifecycle_reconciled",
          metadata,
        },
      });
      await client.auditLog.create({
        data: {
          userId: params.actorUserId || null,
          licenseeId: batch.licenseeId,
          action: "BATCH_LIFECYCLE_RECONCILED",
          entityType: "Batch",
          entityId: batch.id,
          details: metadata,
        },
      });
    }
  }

  const readiness = buildBatchPrintReadiness({
    batchId: batch.id,
    lifecycleState: afterState,
    releasedAt: batch.releasedAt,
    availableToPrint,
    canRepairAutomatically: !params.apply && canRepairAutomatically,
    repairTargetState: targetState,
  });

  return {
    batchId: batch.id,
    beforeState: batch.lifecycleState,
    afterState,
    mutated,
    targetState,
    evidence,
    readiness,
  };
};

export const findPrintLifecycleDriftBatches = async (params: {
  batchId?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  limit?: number;
  tx?: ReconciliationClient;
}) => {
  const client = params.tx || prisma;
  const limit = Math.max(1, Math.min(Number(params.limit || 100), 1000));
  const candidates = await client.batch.findMany({
    where: {
      lifecycleState: BatchLifecycleState.DRAFT,
      ...(params.batchId ? { id: params.batchId } : {}),
      ...(params.licenseeId ? { licenseeId: params.licenseeId } : {}),
      ...(params.manufacturerId ? { manufacturerId: params.manufacturerId } : {}),
      OR: [
        { printedAt: { not: null } },
        { qrCodes: { some: { status: { in: PRINT_EVIDENCE_QR_STATUSES } } } },
        { printJobs: { some: { OR: [{ status: PrintJobStatus.CONFIRMED }, { confirmedAt: { not: null } }] } } },
      ],
    },
    orderBy: [{ updatedAt: "desc" }, { createdAt: "desc" }],
    take: limit,
    select: {
      id: true,
      licenseeId: true,
      manufacturerId: true,
      lifecycleState: true,
      printedAt: true,
      totalCodes: true,
    },
  });

  return Promise.all(
    candidates.map(async (candidate) => ({
      ...candidate,
      reconciliation: await reconcileBatchPrintLifecycle({
        batchId: candidate.id,
        apply: false,
        tx: client,
      }),
    }))
  );
};
