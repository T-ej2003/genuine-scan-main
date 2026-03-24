import { Response } from "express";
import { NotificationAudience, NotificationChannel } from "@prisma/client";

import { AuthRequest } from "../../middleware/auth";
import { createRoleNotifications } from "../../services/notificationService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import { failStopPrintSession, getOrCreatePrintSession } from "../../services/printLifecycleService";
import {
  beginPrintActionIdempotency,
  ensureManufacturerUser,
  getManufacturerPrintJob,
  handleIdempotencyError,
  hashLockToken,
  isLockExpired,
  notifySystemPrintEvent,
  replayIdempotentResponseIfAny,
  reportDirectPrintFailureSchema,
} from "./shared";

export const reportDirectPrintFailure = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = reportDirectPrintFailureSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const jobId = String(req.params.id || "").trim();
    if (!jobId) {
      return res.status(400).json({ success: false, error: "Missing print job id" });
    }

    let idempotency;
    try {
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_fail_stop",
        scope: `job:${jobId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const job = await getManufacturerPrintJob(jobId, user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

    const now = new Date();
    if (isLockExpired(job.createdAt, now)) {
      return res.status(410).json({
        success: false,
        error: "Print lock token expired. Create a new print job to continue secure direct printing.",
      });
    }

    const tokenHash = hashLockToken(parsed.data.printLockToken);
    if (tokenHash !== job.printLockTokenHash) {
      return res.status(403).json({ success: false, error: "Invalid print lock token" });
    }

    const session = await getOrCreatePrintSession({
      id: job.id,
      batchId: job.batchId,
      manufacturerId: job.manufacturerId,
      quantity: job.quantity,
      status: job.status,
      printerRegistrationId: job.printSession?.printerRegistrationId || null,
      printerId: job.printerId || null,
    });

    const failed = await failStopPrintSession({
      printSessionId: session.id,
      printJobId: job.id,
      batchId: job.batchId,
      licenseeId: job.batch.licenseeId || null,
      actorUserId: user.userId,
      reason: parsed.data.reason,
      printItemId: parsed.data.printItemId,
      retries: parsed.data.retries,
      metadata: parsed.data.agentMetadata,
    });

    const alertBody = `Direct-print fail-stop activated for ${job.batch.name}. Reason: ${parsed.data.reason}`;

    await Promise.allSettled([
      notifySystemPrintEvent({
        licenseeId: job.batch.licenseeId,
        orgId: user.orgId || null,
        type: "system_print_job_failed",
        title: "Direct-print fail-stop triggered",
        body: alertBody,
        data: {
          printJobId: job.id,
          printSessionId: session.id,
          incidentId: failed.incident.id,
          frozenCount: failed.frozenCount,
          failedItemId: parsed.data.printItemId || null,
          reason: parsed.data.reason,
          retries: parsed.data.retries ?? 0,
          targetRoute: "/incidents",
        },
        channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
      }),
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "print_fail_stop_incident",
        title: "Print fail-stop incident created",
        body: alertBody,
        licenseeId: job.batch.licenseeId || null,
        orgId: user.orgId || null,
        incidentId: failed.incident.id,
        data: {
          incidentId: failed.incident.id,
          printJobId: job.id,
          printSessionId: session.id,
          frozenCount: failed.frozenCount,
          reason: parsed.data.reason,
          targetRoute: "/incidents",
        },
        channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
      }),
    ]);

    const responsePayload = {
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: session.id,
        incidentId: failed.incident.id,
        frozenCount: failed.frozenCount,
        reason: parsed.data.reason,
      },
    };

    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 202,
      responsePayload,
    });

    return res.status(202).json(responsePayload);
  } catch (e: any) {
    console.error("reportDirectPrintFailure error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};
