import { BatchLifecycleState, PrintJobStatus } from "@prisma/client";

import prisma from "../config/database";
import { evaluateSampleScanPolicy } from "./sampleScanPolicyService";

export type BatchTransitionTarget =
  | "CODES_GENERATED"
  | "PRINT_REQUESTED"
  | "PRINT_ACKNOWLEDGED"
  | "PHYSICAL_PRINT_CONFIRMED"
  | "SAMPLE_SCAN_VERIFIED"
  | "APPROVAL_PENDING"
  | "RELEASED";

export type BatchStateErrorCode =
  | "QR_CODES_REQUIRED"
  | "PRINT_ACK_REQUIRED"
  | "PHYSICAL_CONFIRMATION_REQUIRED"
  | "SAMPLE_SCAN_REQUIRED"
  | "APPROVAL_REQUIRED"
  | "CHECKER_REQUIRED"
  | "MAKER_CANNOT_APPROVE"
  | "BATCH_ALREADY_RELEASED"
  | "QR_NOT_IN_PRINT_JOB"
  | "INVALID_STATE_TRANSITION";

export class BatchStateTransitionError extends Error {
  statusCode: number;
  code: BatchStateErrorCode;
  details?: Record<string, unknown>;

  constructor(code: BatchStateErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "BatchStateTransitionError";
    this.statusCode = 409;
    this.code = code;
    this.details = details;
  }
}

type TransitionBatch = {
  id: string;
  lifecycleState?: BatchLifecycleState | null;
  releasedAt?: Date | string | null;
  totalCodes?: number | null;
};

type TransitionActor = {
  userId?: string | null;
  role?: string | null;
};

type TransitionContext = {
  qrCodeCount?: number | null;
  printJob?: {
    id?: string | null;
    status?: PrintJobStatus | string | null;
    sentAt?: Date | string | null;
    confirmedAt?: Date | string | null;
  } | null;
  sampleScanSatisfied?: boolean | null;
  approvalRequired?: boolean | null;
  approvalSatisfied?: boolean | null;
  makerUserId?: string | null;
  prerequisiteActorUserIds?: Array<string | null | undefined>;
};

type TransitionClient = Pick<typeof prisma, "batch" | "qRCode" | "printJob" | "printAuditEvent" | "auditLog">;

const terminalStates = new Set<BatchLifecycleState>([
  BatchLifecycleState.RELEASED,
  BatchLifecycleState.FAILED,
  BatchLifecycleState.VOIDED,
]);

const stateOrder: Record<BatchLifecycleState, number> = {
  [BatchLifecycleState.DRAFT]: 0,
  [BatchLifecycleState.CODES_GENERATED]: 1,
  [BatchLifecycleState.PRINT_ACKNOWLEDGED]: 2,
  [BatchLifecycleState.PRINT_CONFIRMED]: 3,
  [BatchLifecycleState.SAMPLE_VERIFIED]: 4,
  [BatchLifecycleState.RELEASED]: 5,
  [BatchLifecycleState.FAILED]: -1,
  [BatchLifecycleState.VOIDED]: -1,
};

const transitionRequirement: Partial<Record<BatchTransitionTarget, number>> = {
  PRINT_REQUESTED: 1,
  PRINT_ACKNOWLEDGED: 1,
  PHYSICAL_PRINT_CONFIRMED: 2,
  SAMPLE_SCAN_VERIFIED: 3,
  APPROVAL_PENDING: 4,
  RELEASED: 4,
};

const toState = (value: BatchLifecycleState | string | null | undefined) =>
  (Object.values(BatchLifecycleState) as string[]).includes(String(value || ""))
    ? (value as BatchLifecycleState)
    : BatchLifecycleState.DRAFT;

const hasCodes = (batch: TransitionBatch, context: TransitionContext) =>
  Math.max(0, Number(context.qrCodeCount ?? batch.totalCodes ?? 0)) > 0;

const hasPrintAck = (context: TransitionContext) => Boolean(context.printJob?.sentAt);

const hasPhysicalConfirmation = (context: TransitionContext) =>
  context.printJob?.status === PrintJobStatus.CONFIRMED && Boolean(context.printJob.confirmedAt);

const assertNotTerminal = (batch: TransitionBatch, target: BatchTransitionTarget) => {
  const state = toState(batch.lifecycleState);
  if ((state === BatchLifecycleState.RELEASED || batch.releasedAt) && target !== "RELEASED") {
    throw new BatchStateTransitionError("BATCH_ALREADY_RELEASED", "This batch is already released.");
  }
  if (terminalStates.has(state) && state !== BatchLifecycleState.RELEASED) {
    throw new BatchStateTransitionError("INVALID_STATE_TRANSITION", "This batch is not available for this action.");
  }
};

export const assertBatchTransitionAllowed = (params: {
  batch: TransitionBatch;
  toStatus: BatchTransitionTarget;
  actor?: TransitionActor | null;
  context?: TransitionContext;
}) => {
  const { batch, toStatus } = params;
  const context = params.context || {};
  const state = toState(batch.lifecycleState);
  const order = stateOrder[state];

  if (toStatus === "CODES_GENERATED") {
    assertNotTerminal(batch, toStatus);
    return;
  }

  if (toStatus === "RELEASED" && (state === BatchLifecycleState.RELEASED || batch.releasedAt)) {
    throw new BatchStateTransitionError("BATCH_ALREADY_RELEASED", "This batch is already released.");
  }

  assertNotTerminal(batch, toStatus);

  const requiredOrder = transitionRequirement[toStatus];
  if (requiredOrder !== undefined && order < requiredOrder) {
    if (!hasCodes(batch, context)) {
      throw new BatchStateTransitionError("QR_CODES_REQUIRED", "Generate QR labels before continuing.");
    }
    if (requiredOrder >= 2 && !hasPrintAck(context)) {
      throw new BatchStateTransitionError("PRINT_ACK_REQUIRED", "Print job has not been sent yet.");
    }
    if (requiredOrder >= 3 && !hasPhysicalConfirmation(context)) {
      throw new BatchStateTransitionError(
        "PHYSICAL_CONFIRMATION_REQUIRED",
        "Confirm physical printing before scanning or releasing."
      );
    }
    if (requiredOrder >= 4 && !context.sampleScanSatisfied) {
      throw new BatchStateTransitionError("SAMPLE_SCAN_REQUIRED", "Scan one printed label before release.");
    }
    throw new BatchStateTransitionError("INVALID_STATE_TRANSITION", "Complete the previous batch step first.");
  }

  if ((toStatus === "PRINT_REQUESTED" || toStatus === "PRINT_ACKNOWLEDGED") && !hasCodes(batch, context)) {
    throw new BatchStateTransitionError("QR_CODES_REQUIRED", "Generate QR labels before printing.");
  }
  if (toStatus === "PHYSICAL_PRINT_CONFIRMED" && !hasPrintAck(context)) {
    throw new BatchStateTransitionError("PRINT_ACK_REQUIRED", "Print job has not been sent yet.");
  }
  if (toStatus === "SAMPLE_SCAN_VERIFIED" && !hasPhysicalConfirmation(context)) {
    throw new BatchStateTransitionError(
      "PHYSICAL_CONFIRMATION_REQUIRED",
      "Confirm physical printing before scanning a sample."
    );
  }
  if ((toStatus === "APPROVAL_PENDING" || toStatus === "RELEASED") && !context.sampleScanSatisfied) {
    throw new BatchStateTransitionError("SAMPLE_SCAN_REQUIRED", "Scan one printed label before release.");
  }
  if (toStatus === "RELEASED" && context.approvalRequired && !context.approvalSatisfied) {
    throw new BatchStateTransitionError(
      "APPROVAL_REQUIRED",
      "A second authorized checker must approve this high-value release."
    );
  }
  if (toStatus === "RELEASED" && context.approvalSatisfied && params.actor?.userId) {
    const actorId = params.actor.userId;
    if (context.makerUserId && context.makerUserId === actorId) {
      throw new BatchStateTransitionError("MAKER_CANNOT_APPROVE", "The release checker must be a different user.");
    }
    if ((context.prerequisiteActorUserIds || []).filter(Boolean).includes(actorId)) {
      throw new BatchStateTransitionError("CHECKER_REQUIRED", "A different authorized checker must approve this release.");
    }
  }
};

const latestBatchPrintJob = async (client: TransitionClient, batchId: string) =>
  client.printJob.findFirst({
    where: { batchId },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    select: {
      id: true,
      status: true,
      sentAt: true,
      confirmedAt: true,
      itemCount: true,
      quantity: true,
    },
  });

export const assertBatchTransitionAllowedFromDb = async (params: {
  batchId: string;
  toStatus: BatchTransitionTarget;
  actor?: TransitionActor | null;
  printJobId?: string | null;
  approvalRequired?: boolean;
  approvalSatisfied?: boolean;
  tx?: TransitionClient;
}) => {
  const client = params.tx || prisma;
  const batch = await client.batch.findUnique({
    where: { id: params.batchId },
    select: {
      id: true,
      lifecycleState: true,
      releasedAt: true,
      totalCodes: true,
      sampleScanPolicy: true,
    },
  });
  if (!batch) {
    throw new BatchStateTransitionError("INVALID_STATE_TRANSITION", "Batch not found.");
  }

  const [qrCodeCount, printJob] = await Promise.all([
    client.qRCode.count({ where: { batchId: batch.id } }),
    params.printJobId
      ? client.printJob.findUnique({
          where: { id: params.printJobId },
          select: { id: true, status: true, sentAt: true, confirmedAt: true, itemCount: true, quantity: true },
        })
      : latestBatchPrintJob(client, batch.id),
  ]);

  const sampleScanPolicy =
    (params.toStatus === "APPROVAL_PENDING" || params.toStatus === "RELEASED") && printJob?.id
      ? await evaluateSampleScanPolicy({
          batchId: batch.id,
          printJobId: printJob.id,
          policy: batch.sampleScanPolicy,
          quantity: printJob.itemCount || printJob.quantity || batch.totalCodes || qrCodeCount,
          tx: client,
        })
      : null;

  assertBatchTransitionAllowed({
    batch,
    toStatus: params.toStatus,
    actor: params.actor || null,
    context: {
      qrCodeCount,
      printJob,
      sampleScanSatisfied: sampleScanPolicy ? sampleScanPolicy.satisfied : null,
      approvalRequired: Boolean(params.approvalRequired),
      approvalSatisfied: params.approvalSatisfied || !params.approvalRequired,
    },
  });

  return { batch, qrCodeCount, printJob, sampleScanPolicy };
};

export const markBatchPrintAcknowledged = async (params: {
  batchId: string;
  printJobId: string;
  actorUserId?: string | null;
  tx?: Pick<typeof prisma, "batch" | "qRCode" | "printJob" | "printAuditEvent" | "auditLog">;
}) => {
  const client = params.tx || prisma;
  await assertBatchTransitionAllowedFromDb({
    batchId: params.batchId,
    printJobId: params.printJobId,
    toStatus: "PRINT_ACKNOWLEDGED",
    actor: { userId: params.actorUserId || null },
    tx: client,
  });
  return client.batch.updateMany({
    where: {
      id: params.batchId,
      lifecycleState: {
        in: [BatchLifecycleState.DRAFT, BatchLifecycleState.CODES_GENERATED],
      },
    },
    data: { lifecycleState: BatchLifecycleState.PRINT_ACKNOWLEDGED },
  });
};
