import { Prisma, PrintJobStatus } from "@prisma/client";

import prisma from "../config/database";
import { assertBatchTransitionAllowedFromDb, BatchStateTransitionError } from "./batchStateMachineService";
import { markBatchSampleVerifiedIfSatisfied } from "./sampleScanPolicyService";

export const extractPublicCodeFromSampleScan = (value: string) => {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";

  try {
    const parsed = new URL(trimmed);
    const segments = parsed.pathname.split("/").filter(Boolean);
    const verifyIndex = segments.findIndex((segment) => segment === "verify");
    if (verifyIndex >= 0 && segments[verifyIndex + 1]) {
      return decodeURIComponent(segments[verifyIndex + 1]);
    }
  } catch {
    // A raw public code is expected and does not need URL parsing.
  }

  return trimmed;
};

export const sampleScanBelongsToPrintJob = (params: {
  printJobId: string;
  qrPrintJobId?: string | null;
  printItemSessionJobId?: string | null;
}) =>
  Boolean(
    params.printJobId &&
      (params.qrPrintJobId === params.printJobId || params.printItemSessionJobId === params.printJobId)
  );

export const recordPrintJobSampleScan = async (params: {
  printJobId: string;
  actorId: string;
  scannedValue: string;
}) => {
  const publicCode = extractPublicCodeFromSampleScan(params.scannedValue);
  if (!publicCode) {
    throw Object.assign(new Error("Sample scan code is required."), { statusCode: 400 });
  }

  return prisma.$transaction(async (tx) => {
    const job = await tx.printJob.findUnique({
      where: { id: params.printJobId },
      select: {
        id: true,
        batchId: true,
        status: true,
        confirmedAt: true,
        manufacturerId: true,
        batch: { select: { licenseeId: true } },
      },
    });
    if (!job) {
      throw Object.assign(new Error("Print job not found."), { statusCode: 404 });
    }
    if (job.status !== PrintJobStatus.CONFIRMED || !job.confirmedAt) {
      throw new BatchStateTransitionError(
        "PHYSICAL_CONFIRMATION_REQUIRED",
        "Confirm physical printing before scanning a sample."
      );
    }
    await assertBatchTransitionAllowedFromDb({
      batchId: job.batchId,
      printJobId: job.id,
      toStatus: "SAMPLE_SCAN_VERIFIED",
      actor: { userId: params.actorId },
      tx,
    });

    const qr = await tx.qRCode.findUnique({
      where: { code: publicCode },
      select: {
        id: true,
        code: true,
        displayCode: true,
        batchId: true,
        printJobId: true,
        printItem: {
          select: {
            id: true,
            printSession: {
              select: {
                printJobId: true,
              },
            },
          },
        },
      },
    });

    const belongs = qr
      ? sampleScanBelongsToPrintJob({
          printJobId: job.id,
          qrPrintJobId: qr.printJobId,
          printItemSessionJobId: qr.printItem?.printSession.printJobId || null,
        })
      : false;

    if (!qr || !belongs) {
      await tx.printAuditEvent.create({
        data: {
          batchId: job.batchId,
          printJobId: job.id,
          qrCodeId: qr?.id || null,
          actorId: params.actorId,
          eventType: "sample_scan_rejected",
          metadata: {
            publicCode,
            scanResult: qr ? "wrong_print_job" : "unknown_code",
            expectedPrintJobId: job.id,
            scannedQrPrintJobId: qr?.printJobId || null,
            scannedPrintItemSessionJobId: qr?.printItem?.printSession.printJobId || null,
          } as Prisma.InputJsonValue,
        },
      });
      throw new BatchStateTransitionError("QR_NOT_IN_PRINT_JOB", "This sample QR does not belong to this print job.");
    }

    const existing = await tx.printAuditEvent.findFirst({
      where: {
        batchId: job.batchId,
        printJobId: job.id,
        qrCodeId: qr.id,
        eventType: "sample_scan_verified",
      },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      select: { id: true, eventType: true, createdAt: true },
    });
    if (existing) {
      const policyResult = await markBatchSampleVerifiedIfSatisfied({
        batchId: job.batchId,
        printJobId: job.id,
        tx,
      });
      return {
        printJobId: job.id,
        qrCodeId: qr.id,
        publicCode,
        displayCode: qr.displayCode || null,
        printAuditEventId: existing.id,
        eventType: existing.eventType,
        createdAt: existing.createdAt.toISOString(),
        sampleScanPolicy: policyResult || null,
        idempotent: true,
      };
    }

    const event = await tx.printAuditEvent.create({
      data: {
        batchId: job.batchId,
        printJobId: job.id,
        qrCodeId: qr.id,
        actorId: params.actorId,
        eventType: "sample_scan_verified",
        metadata: {
          publicCode,
          displayCode: qr.displayCode || null,
          scanResult: "matched_print_job",
          verifiedAt: new Date().toISOString(),
        } as Prisma.InputJsonValue,
      },
    });

    await tx.auditLog.create({
      data: {
        userId: params.actorId,
        licenseeId: job.batch.licenseeId,
        action: "PRINT_SAMPLE_SCAN_VERIFIED",
        entityType: "PrintJob",
        entityId: job.id,
        details: {
          qrCodeId: qr.id,
          publicCode,
          displayCode: qr.displayCode || null,
          printAuditEventId: event.id,
        } as Prisma.InputJsonValue,
      },
    });

    const policyResult = await markBatchSampleVerifiedIfSatisfied({
      batchId: job.batchId,
      printJobId: job.id,
      tx,
    });

    return {
      printJobId: job.id,
      qrCodeId: qr.id,
      publicCode,
      displayCode: qr.displayCode || null,
      printAuditEventId: event.id,
      eventType: event.eventType,
      createdAt: event.createdAt.toISOString(),
      sampleScanPolicy: policyResult || null,
    };
  });
};
