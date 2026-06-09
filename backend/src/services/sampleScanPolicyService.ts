import { BatchLifecycleState } from "@prisma/client";

import prisma from "../config/database";

type SampleScanPolicyClient = Pick<typeof prisma, "batch" | "qRCode"> & {
  printAuditEvent?: Pick<typeof prisma.printAuditEvent, "findMany">;
};

export type SampleScanPolicy =
  | { type: "ONE_PER_PRINT_JOB" }
  | { type: "ONE_PER_ROLL" }
  | { type: "ONE_PER_N_LABELS"; n: number }
  | { type: "PERCENTAGE"; percentage: number; min: number };

export type SampleScanPolicyResult = {
  satisfied: boolean;
  required: number;
  passed: number;
  missing: number;
  policy: SampleScanPolicy;
};

const DEFAULT_POLICY: SampleScanPolicy = { type: "ONE_PER_PRINT_JOB" };

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

export const normalizeSampleScanPolicy = (value: unknown): SampleScanPolicy => {
  const raw = asRecord(value);
  const type = String(raw?.type || "").trim().toUpperCase();

  if (type === "ONE_PER_ROLL") return { type: "ONE_PER_ROLL" };
  if (type === "ONE_PER_N_LABELS") {
    const n = Math.floor(Number(raw?.n || 0));
    return { type: "ONE_PER_N_LABELS", n: Number.isFinite(n) && n > 0 ? Math.min(n, 10000) : 100 };
  }
  if (type === "PERCENTAGE") {
    const percentage = Math.max(0.01, Math.min(100, Number(raw?.percentage || 0)));
    const min = Math.max(1, Math.min(10000, Math.floor(Number(raw?.min || 1))));
    return { type: "PERCENTAGE", percentage: Number.isFinite(percentage) ? percentage : 1, min };
  }
  return DEFAULT_POLICY;
};

export const calculateRequiredSampleScans = (policy: SampleScanPolicy, quantity: number) => {
  const safeQuantity = Math.max(1, Math.floor(Number(quantity || 0)));
  if (policy.type === "ONE_PER_N_LABELS") return Math.max(1, Math.ceil(safeQuantity / Math.max(1, policy.n)));
  if (policy.type === "PERCENTAGE") {
    return Math.max(policy.min, Math.ceil((safeQuantity * policy.percentage) / 100));
  }
  return 1;
};

export const evaluateSampleScanPolicy = async (params: {
  batchId: string;
  printJobId: string;
  policy?: unknown;
  quantity?: number | null;
  tx?: SampleScanPolicyClient;
}): Promise<SampleScanPolicyResult> => {
  const client: SampleScanPolicyClient = params.tx || prisma;
  const policy = normalizeSampleScanPolicy(params.policy);
  const quantity =
    Number.isFinite(Number(params.quantity)) && Number(params.quantity) > 0
      ? Number(params.quantity)
      : await client.qRCode.count({ where: { batchId: params.batchId } });
  const required = calculateRequiredSampleScans(policy, quantity);

  const passedRows = client.printAuditEvent?.findMany
    ? await client.printAuditEvent.findMany({
        where: {
          batchId: params.batchId,
          printJobId: params.printJobId,
          eventType: "sample_scan_verified",
          qrCodeId: { not: null },
        },
        select: {
          batchId: true,
          printJobId: true,
          eventType: true,
          qrCodeId: true,
        },
      })
    : [];

  const passed = new Set(
    passedRows
      .filter((row) => row.batchId === params.batchId)
      .filter((row) => row.printJobId === params.printJobId)
      .filter((row) => row.eventType === "sample_scan_verified")
      .map((row) => row.qrCodeId)
      .filter((qrCodeId): qrCodeId is string => Boolean(qrCodeId))
  ).size;
  return {
    satisfied: passed >= required,
    required,
    passed,
    missing: Math.max(0, required - passed),
    policy,
  };
};

export const markBatchSampleVerifiedIfSatisfied = async (params: {
  batchId: string;
  printJobId: string;
  tx?: SampleScanPolicyClient;
}) => {
  const client: SampleScanPolicyClient = params.tx || prisma;
  const batch = await client.batch.findUnique({
    where: { id: params.batchId },
    select: { id: true, sampleScanPolicy: true, totalCodes: true, lifecycleState: true },
  });
  if (!batch || batch.lifecycleState === BatchLifecycleState.RELEASED) return null;

  const result = await evaluateSampleScanPolicy({
    batchId: batch.id,
    printJobId: params.printJobId,
    policy: batch.sampleScanPolicy,
    quantity: batch.totalCodes,
    tx: client,
  });
  if (!result.satisfied) return result;
  if (
    batch.lifecycleState !== BatchLifecycleState.PRINT_CONFIRMED &&
    batch.lifecycleState !== BatchLifecycleState.SAMPLE_VERIFIED
  ) {
    return result;
  }

  await client.batch.update({
    where: { id: batch.id },
    data: { lifecycleState: BatchLifecycleState.SAMPLE_VERIFIED },
  });
  return result;
};
