import type { ApiResponse } from "@/lib/api/internal-client-core";

export type FriendlyErrorKind =
  | "unauthenticated"
  | "unauthorized"
  | "conflict"
  | "step_up_required"
  | "timeout_unknown"
  | "network"
  | "email_failed"
  | "validation"
  | "server"
  | "unknown";

export type FriendlyError = {
  kind: FriendlyErrorKind;
  title: string;
  description: string;
  destructive?: boolean;
  unknownOutcome?: boolean;
};

const CONFLICT_MESSAGE = "A brand/admin with these details already exists. Review the existing record or use different details.";

const EMAIL_ERROR_MESSAGES: Record<string, string> = {
  SMTP_CONFIG_MISSING: "Email is not configured for this environment.",
  SMTP_AUTH_FAILED: "The mail provider rejected the configured mailbox credentials.",
  SMTP_CONNECTION_FAILED: "The mail provider could not be reached.",
  SMTP_TLS_FAILED: "The mail provider rejected the secure connection.",
  SMTP_TIMEOUT: "The mail provider did not respond in time.",
  SMTP_RECIPIENT_REJECTED: "The mail provider rejected the recipient.",
  SMTP_NO_ACCEPTED_RECIPIENTS: "Email acceptance could not be confirmed by the mail provider.",
  SMTP_SEND_FAILED: "The mail provider could not deliver the message.",
  EMAIL_DISABLED: "Email delivery is disabled for this environment.",
  EMAIL_DRY_RUN: "Email delivery is in test mode and no message was sent.",
  UNKNOWN_EMAIL_ERROR: "Email acceptance could not be confirmed.",
};

export function friendlyEmailDeliveryMessage(code?: string | null) {
  const normalized = String(code || "").trim().toUpperCase();
  return EMAIL_ERROR_MESSAGES[normalized] || "Invite email could not be accepted by the mail provider. Copy the invite link or retry sending.";
}

export function getInviteDeliveryState(data: any) {
  const invite = data?.invite || data?.adminInvite || data || {};
  const emailSent = invite.emailSent === true || invite.emailDelivered === true;
  const emailAttempted = invite.emailAttempted === true || invite.attempted === true;
  const emailErrorCode = String(invite.emailErrorCode || invite.deliveryError || "").trim() || null;
  const emailDiagnostic = String(invite.emailDiagnostic || invite.diagnostic || "").trim() || null;
  const inviteLink = String(invite.inviteLink || data?.inviteLink || "").trim();
  const created = Boolean(invite.created ?? invite.inviteId ?? inviteLink);
  return { created, emailAttempted, emailSent, emailErrorCode, emailDiagnostic, inviteLink };
}

export function classifyApiError(response: Partial<ApiResponse> & { status?: number; unknownOutcome?: boolean } = {}): FriendlyError {
  const status = Number(response.status || 0);
  const code = String(response.code || "").trim().toUpperCase();

  if (response.unknownOutcome || code === "REQUEST_TIMEOUT" || code === "UNKNOWN_OUTCOME") {
    return {
      kind: "timeout_unknown",
      title: "Still checking this request",
      description: "The request timed out before the server confirmed the result. We will refresh and reconcile the latest records.",
      destructive: false,
      unknownOutcome: true,
    };
  }

  if (status === 401 || code === "UNAUTHENTICATED") {
    return {
      kind: "unauthenticated",
      title: "Sign in required",
      description: "Your session has expired. Please sign in again.",
      destructive: true,
    };
  }

  if (status === 403 || code === "FORBIDDEN") {
    return {
      kind: "unauthorized",
      title: "Access denied",
      description: "Your account does not have permission to perform this action.",
      destructive: true,
    };
  }

  if (status === 428 || code === "STEP_UP_REQUIRED") {
    return {
      kind: "step_up_required",
      title: "Verification required",
      description: "Complete verification, then retry creating the brand.",
      destructive: false,
    };
  }

  if (status === 409 || code.includes("CONFLICT") || code.includes("DUPLICATE")) {
    return {
      kind: "conflict",
      title: "Already exists",
      description: CONFLICT_MESSAGE,
      destructive: true,
    };
  }

  if (code.includes("EMAIL") || code.startsWith("SMTP_")) {
    return {
      kind: "email_failed",
      title: "Invite email not sent",
      description: friendlyEmailDeliveryMessage(code),
      destructive: true,
    };
  }

  if (code === "NETWORK_ERROR" || status === 0) {
    return {
      kind: "network",
      title: "Network issue",
      description: "We could not reach the server. Check the connection and retry.",
      destructive: true,
    };
  }

  if (status >= 400 && status < 500) {
    return {
      kind: "validation",
      title: "Request needs attention",
      description: "Please review the details and try again.",
      destructive: true,
    };
  }

  if (status >= 500) {
    return {
      kind: "server",
      title: "Server issue",
      description: "The server could not complete the request. Please retry in a moment.",
      destructive: true,
    };
  }

  return {
    kind: "unknown",
    title: "Action could not be completed",
    description: "Please retry. If this continues, contact support.",
    destructive: true,
  };
}
