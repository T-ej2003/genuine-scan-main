import { randomUUID } from "crypto";

import { claimSupportResponseEmails, completeSupportResponseEmail } from "../rls-waves/session-b/b03/repositoryFunctions";
import { withB03SupportEmailWorkerContext } from "../rls-waves/session-b/b03/systemContext";
import { withDistributedLease } from "./distributedLeaseService";
import { sendSupportIssueReply } from "./supportIntakeMailService";

type DeliveryData = {
  recipient?: unknown;
  reporterName?: unknown;
  referenceCode?: unknown;
  subject?: unknown;
  responderEmail?: unknown;
  responderUserId?: unknown;
  claimToken?: unknown;
};

let timer: NodeJS.Timeout | null = null;

export const flushSupportResponseEmailOutbox = async () => {
  const claimToken = randomUUID();
  const claims = await withB03SupportEmailWorkerContext(
    { jobId: `support-email-claim:${claimToken}`, requestId: claimToken },
    // shortcut: claim one at a time so a crash cannot strand unsent rows in the claimed batch.
    (db) => claimSupportResponseEmails(db, { attemptedAt: new Date(), batchSize: 1 })
  );
  for (const claim of claims) {
    const data = claim.data as DeliveryData;
    let status: "SENT" | "FAILED" | "UNKNOWN" | "DRY_RUN" = "UNKNOWN";
    let errorCode: string | null = "INVALID_DELIVERY_PAYLOAD";
    let providerMessageId: string | null = null;
    if (data && typeof data.recipient === "string" && typeof data.subject === "string" &&
        data.claimToken === claimToken) {
      try {
        const result = await sendSupportIssueReply({
          toAddress: data.recipient,
          subject: data.subject,
          message: claim.body,
          reporterName: typeof data.reporterName === "string" ? data.reporterName : null,
          referenceCode: typeof data.referenceCode === "string" ? data.referenceCode : null,
          responderEmail: typeof data.responderEmail === "string" ? data.responderEmail : null,
        });
        errorCode = result.errorCode || null;
        providerMessageId = result.providerMessageId || null;
        status = result.delivered ? "SENT" : errorCode === "EMAIL_DRY_RUN" ? "DRY_RUN"
          : (!result.attempted || ["SMTP_CONFIG_MISSING", "SMTP_AUTH_FAILED", "SMTP_CONNECTION_FAILED",
            "SMTP_TLS_FAILED", "SMTP_RECIPIENT_REJECTED", "SMTP_NO_ACCEPTED_RECIPIENTS", "EMAIL_DISABLED"].includes(errorCode || ""))
            ? "FAILED" : "UNKNOWN";
      } catch {
        errorCode = "EMAIL_DELIVERY_OUTCOME_UNKNOWN";
      }
    }
    try {
      await withB03SupportEmailWorkerContext({
        jobId: claim.id,
        requestId: randomUUID(),
        organizationId: claim.organizationId,
        licenseeId: claim.licenseeId,
        initiatingUserId: typeof data?.responderUserId === "string" ? data.responderUserId : null,
      }, (db) => completeSupportResponseEmail(db, {
        notificationId: claim.id, claimToken, status, errorCode, providerMessageId,
      }));
    } catch (error) {
      console.error("Support response email completion failed", {
        notificationId: claim.id,
        code: typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : "UNKNOWN",
      });
    }
  }
};

export const startSupportResponseEmailOutboxWorker = () => {
  if (timer || process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS === "true") return;
  timer = setInterval(() => {
    void withDistributedLease("support-response-email-outbox-worker", 90_000, flushSupportResponseEmailOutbox)
      .catch(() => console.error("Support response email outbox flush failed"));
  }, 30_000);
  timer.unref?.();
};

export const stopSupportResponseEmailOutboxWorker = () => {
  if (timer) clearInterval(timer);
  timer = null;
};
