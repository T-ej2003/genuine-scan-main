import { randomBytes } from "crypto";
import { PrintDispatchMode, PrintJobStatus, QRStatus } from "@prisma/client";
import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "../../services/qrTokenService";
import { createAuditLog } from "../../services/auditService";
import { createUserNotification } from "../../services/notificationService";
import {
  supportsNetworkDirectPayloadType,
} from "../../services/printPayloadService";
import { startNetworkDirectDispatch } from "../../services/networkDirectPrintService";
import { startNetworkIppDispatch } from "../../services/networkIppPrintService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import { sanitizePrinterActionError } from "../../utils/printerUserFacingErrors";
import {
  beginPrintActionIdempotency,
  createPrintJobSchema,
  describePrintDispatchMode,
  ensureManufacturerUser,
  ensureSelectedPrinterReady,
  generatePrintJobNumber,
  getLockExpiresAt,
  handleIdempotencyError,
  hashLockToken,
  notifySystemPrintEvent,
  replayIdempotentResponseIfAny,
} from "./shared";

export const createPrintJob = async (req: AuthRequest, res: any) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = createPrintJobSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    let idempotency;
    try {
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_create",
        scope: `user:${user.userId}:batch:${parsed.data.batchId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const { batchId, printerId, quantity, rangeStart, rangeEnd, reprintOfJobId, reprintReason } = parsed.data;
    const batch = await prisma.batch.findFirst({
      where: { id: batchId, manufacturerId: user.userId },
      select: { id: true, name: true, licenseeId: true, manufacturerId: true },
    });
    if (!batch) {
      return res.status(404).json({ success: false, error: "Batch not found or not assigned to you" });
    }

    const printerSelection = await ensureSelectedPrinterReady({
      printerId,
      userId: user.userId,
      orgId: user.orgId || null,
      licenseeId: batch.licenseeId || null,
    });
    if (
      printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT &&
      !supportsNetworkDirectPayloadType(printerSelection.payloadType)
    ) {
      return res.status(409).json({
        success: false,
        error: "Network-direct printing currently supports registered ZPL, TSPL, EPL, and CPCL printers only.",
      });
    }

    const printLockToken = randomBytes(24).toString("base64url");
    const printLockTokenHash = hashLockToken(printLockToken);
    const now = new Date();
    const expAt = getQrTokenExpiryDate(now);

    const created = await prisma.$transaction(
      async (tx) => {
        const rangeFilter =
          rangeStart && rangeEnd
            ? Prisma.sql`AND q."code" >= ${rangeStart} AND q."code" <= ${rangeEnd}`
            : Prisma.empty;

        const reservedRows = await tx.$queryRaw<
          Array<{ id: string; code: string; licenseeId: string; batchId: string | null }>
        >(Prisma.sql`
          SELECT q."id", q."code", q."licenseeId", q."batchId"
          FROM "QRCode" q
          WHERE q."batchId" = ${batch.id}
            AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
            AND q."printJobId" IS NULL
            ${rangeFilter}
          ORDER BY q."code" ASC
          FOR UPDATE SKIP LOCKED
          LIMIT ${quantity};
        `);

        if (reservedRows.length < quantity) {
          throw new Error(`NOT_ENOUGH_CODES:${reservedRows.length}`);
        }

        const prepared = reservedRows.map((qr) => {
          const nonce = randomNonce();
          const payload = {
            qr_id: qr.id,
            batch_id: qr.batchId,
            licensee_id: qr.licenseeId,
            manufacturer_id: batch.manufacturerId || null,
            iat: Math.floor(now.getTime() / 1000),
            exp: Math.floor(expAt.getTime() / 1000),
            nonce,
          };
          const token = signQrPayload(payload);
          const tokenHash = hashToken(token);
          return { qr, nonce, tokenHash };
        });

        const createdJob = await tx.printJob.create({
          data: {
            jobNumber: generatePrintJobNumber(),
            batchId: batch.id,
            manufacturerId: user.userId,
            printerId: printerSelection.printer.id,
            quantity,
            itemCount: prepared.length,
            printMode: printerSelection.printMode,
            payloadType: printerSelection.payloadType,
            rangeStart: rangeStart || null,
            rangeEnd: rangeEnd || null,
            reprintOfJobId: reprintOfJobId || null,
            reprintReason: reprintReason || null,
            printLockTokenHash,
            status: PrintJobStatus.PENDING,
          },
        });

        const values = prepared.map((item) =>
          Prisma.sql`(${item.qr.id}, ${item.nonce}, ${item.tokenHash}, ${now}, ${expAt})`
        );

        const updatedCount = await tx.$executeRaw(Prisma.sql`
          UPDATE "QRCode" AS q
          SET
            "status" = CAST(${QRStatus.ACTIVATED} AS "QRStatus"),
            "tokenNonce" = v."tokenNonce",
            "tokenIssuedAt" = v."tokenIssuedAt",
            "tokenExpiresAt" = v."tokenExpiresAt",
            "tokenHash" = v."tokenHash",
            "printJobId" = ${createdJob.id}
          FROM (
            VALUES ${Prisma.join(values)}
          ) AS v("id", "tokenNonce", "tokenHash", "tokenIssuedAt", "tokenExpiresAt")
          WHERE q."id" = v."id"
            AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
            AND q."printJobId" IS NULL;
        `);

        if (Number(updatedCount) !== prepared.length) {
          throw new Error("BATCH_BUSY");
        }

        const session = await tx.printSession.create({
          data: {
            printJobId: createdJob.id,
            batchId: batch.id,
            manufacturerId: user.userId,
            printerRegistrationId:
              printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
                ? printerSelection.printer.printerRegistrationId || printerSelection.printerStatus?.registrationId || null
                : null,
            printerId: printerSelection.printer.id,
            status: "ACTIVE",
            totalItems: prepared.length,
          },
        });

        await tx.printItem.createMany({
          data: prepared.map((item) => ({
            printSessionId: session.id,
            qrCodeId: item.qr.id,
            code: item.qr.code,
            state: "RESERVED",
          })),
        });

        return {
          job: createdJob,
          session,
          preparedCount: prepared.length,
        };
      },
      { timeout: 30000, maxWait: 10000 }
    );

    await createAuditLog({
      userId: user.userId,
      licenseeId: batch.licenseeId,
      action: "CREATED",
      entityType: "PrintJob",
      entityId: created.job.id,
      details: {
        batchId: batch.id,
        quantity,
        rangeStart: rangeStart || null,
        rangeEnd: rangeEnd || null,
        mode: printerSelection.printMode,
        printerId: printerSelection.printer.id,
        printerName: printerSelection.printer.name,
        printSessionId: created.session.id,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    const responsePayload = {
      success: true,
      data: {
        printJobId: created.job.id,
        printSessionId: created.session.id,
        printLockToken: printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT ? printLockToken : null,
        quantity,
        tokenCount: created.preparedCount,
        mode: printerSelection.printMode,
        lockExpiresAt: getLockExpiresAt(created.job.createdAt).toISOString(),
        printer: {
          id: printerSelection.printer.id,
          name: printerSelection.printer.name,
          connectionType: printerSelection.printer.connectionType,
          commandLanguage: printerSelection.printer.commandLanguage,
          ipAddress: printerSelection.printer.ipAddress,
          host: (printerSelection.printer as any).host || null,
          port: printerSelection.printer.port,
          resourcePath: (printerSelection.printer as any).resourcePath || null,
          tlsEnabled: (printerSelection.printer as any).tlsEnabled ?? null,
          printerUri: (printerSelection.printer as any).printerUri || null,
          deliveryMode: (printerSelection.printer as any).deliveryMode || null,
          gatewayId: (printerSelection.printer as any).gatewayId || null,
          nativePrinterId: printerSelection.printer.nativePrinterId,
        },
        printerStatus: printerSelection.printerStatus,
      },
    };

    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 201,
      responsePayload,
    });

    try {
      await createUserNotification({
        userId: user.userId,
        licenseeId: batch.licenseeId,
        type: "manufacturer_print_job_created",
        title:
          printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT
            ? "Network-direct job prepared"
            : printerSelection.printMode === PrintDispatchMode.NETWORK_IPP
              ? "Network IPP job prepared"
              : "Direct-print job prepared",
        body: `${describePrintDispatchMode(printerSelection.printMode)} session ready for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
      await notifySystemPrintEvent({
        licenseeId: batch.licenseeId,
        orgId: user.orgId || null,
        type: "system_print_job_created",
        title: "System print job created",
        body: `${describePrintDispatchMode(printerSelection.printMode)} print job created for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
    } catch (notifyError) {
      console.error("createPrintJob notification error:", notifyError);
    }

    if (printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT) {
      await startNetworkDirectDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      });
    } else if (printerSelection.printMode === PrintDispatchMode.NETWORK_IPP) {
      await startNetworkIppDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      });
    }

    return res.status(201).json(responsePayload);
  } catch (e: any) {
    console.error("createPrintJob error:", e);
    const msg = String(e?.message || "");
    if (msg.includes("BATCH_BUSY")) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    if (msg.startsWith("NOT_ENOUGH_CODES:")) {
      const available = Number(msg.split(":")[1] || "0");
      return res.status(400).json({
        success: false,
        error: `Not enough unprinted codes. Available: ${available}`,
      });
    }
    if (msg.includes("PRINTER_NOT_TRUSTED")) {
      const printerStatus = (e as any)?.printerStatus || null;
      return res.status(409).json({
        success: false,
        error:
          "Printer is not ready for secure issuance. Reconnect print agent or switch to compatibility-ready local printer profile.",
        data: { printerStatus },
      });
    }
    if (msg.includes("PRINTER_NOT_FOUND")) {
      return res.status(404).json({ success: false, error: "Registered printer not found for this manufacturer scope." });
    }
    if (msg.includes("PRINTER_INACTIVE")) {
      return res.status(409).json({ success: false, error: "Selected printer profile is inactive." });
    }
    if (msg.includes("PRINTER_SELECTION_MISMATCH")) {
      const printerStatus = (e as any)?.printerStatus || null;
      return res.status(409).json({
        success: false,
        error: "Selected local printer does not match the active workstation printer. Switch printer selection and retry.",
        data: { printerStatus },
      });
    }
    if (msg.includes("PRINTER_NETWORK_CONFIG_INVALID")) {
      return res.status(409).json({ success: false, error: "Selected network printer is missing IP address or TCP port." });
    }
    if (msg.includes("PRINTER_NETWORK_LANGUAGE_UNSUPPORTED")) {
      return res.status(409).json({
        success: false,
        error:
          "Selected network printer uses a language that is not available for network-direct dispatch. Use ZPL, TSPL, EPL, or CPCL, or switch to the local agent path.",
      });
    }
    if (msg.includes("PRINTER_NETWORK_UNREACHABLE")) {
      return res.status(409).json({
        success: false,
        error: sanitizePrinterActionError((e as any)?.reason, "The saved factory printer could not be reached."),
      });
    }
    if (msg.includes("PRINTER_GATEWAY_CONFIG_INVALID")) {
      return res.status(409).json({
        success: false,
        error: "Selected gateway-backed IPP printer is missing gateway credentials. Re-save the printer profile and provision the site gateway.",
      });
    }
    if (msg.includes("PRINTER_GATEWAY_OFFLINE")) {
      return res.status(409).json({
        success: false,
        error: sanitizePrinterActionError((e as any)?.reason, "The site print connector needs attention before this printer can be used."),
      });
    }
    if (msg.includes("PRINTER_IPP_FORMAT_UNSUPPORTED")) {
      return res.status(409).json({
        success: false,
        error: sanitizePrinterActionError(
          (e as any)?.reason,
          "This office printer does not support the required MSCQR print format."
        ),
      });
    }
    if (msg.includes("PRINTER_IPP_UNREACHABLE")) {
      return res.status(409).json({
        success: false,
        error: sanitizePrinterActionError((e as any)?.reason, "The saved office printer could not be reached."),
      });
    }
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(e?.message, "This print job could not be created."),
    });
  }
};
