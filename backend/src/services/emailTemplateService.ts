const MSCQR_NAME = "MSCQR";
const MSCQR_URL = "https://www.mscqr.com";
const MSCQR_CONTACT = "administration@mscqr.com";

const escapeHtml = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const ctaText = (label: string, url: string) => `${label}: ${url}`;

export const mscqrIdentityText = () => `${MSCQR_NAME}\n${MSCQR_URL}\n${MSCQR_CONTACT}`;

export const appendMscqrIdentityToText = (body: string) => {
  const text = String(body || "").trim();
  if (text.includes(MSCQR_URL) && text.includes(MSCQR_CONTACT)) return text;
  return `${text}\n\n--\n${mscqrIdentityText()}`;
};

export const mscqrFooterHtml = () =>
  `<p style="margin:24px 0 0;color:#64748b;font-size:13px;line-height:1.6;">${MSCQR_NAME}<br><a href="${MSCQR_URL}" style="color:#0f766e;">${MSCQR_URL}</a><br>${MSCQR_CONTACT}</p>`;

export const renderActionEmail = (params: {
  heading: string;
  intro: string;
  actionLabel: string;
  actionUrl: string;
  expiryText?: string | null;
  workspaceName?: string | null;
  extraText?: string | null;
  reason?: string | null;
}) => {
  const reason = params.reason || "You received this email because an MSCQR account or product-protection workflow was started for this address.";
  const expiry = params.expiryText ? `\n\nThis link expires ${params.expiryText}.` : "";
  const workspace = params.workspaceName ? `\n\nWorkspace: ${params.workspaceName}.` : "";
  const extra = params.extraText ? `\n\n${params.extraText.trim()}` : "";
  const text = appendMscqrIdentityToText(
    `${params.intro.trim()}${workspace}\n\n${ctaText(params.actionLabel, params.actionUrl)}${expiry}${extra}\n\n${reason}\n\nIf you were not expecting this, you can ignore this email.`
  );

  const html = `
    <div style="margin:0;padding:0;background:#f8fafc;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
      <div style="max-width:640px;margin:0 auto;padding:28px 18px;">
        <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
          <p style="margin:0 0 12px;color:#0f766e;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;font-size:12px;">MSCQR</p>
          <h1 style="margin:0 0 16px;font-size:24px;line-height:1.25;color:#0f172a;">${escapeHtml(params.heading)}</h1>
          <p style="margin:0 0 16px;line-height:1.65;color:#334155;">${escapeHtml(params.intro)}</p>
          ${params.workspaceName ? `<p style="margin:0 0 16px;line-height:1.65;color:#334155;"><strong>Workspace:</strong> ${escapeHtml(params.workspaceName)}</p>` : ""}
          <p style="margin:0 0 20px;"><a href="${escapeHtml(params.actionUrl)}" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:700;border-radius:8px;padding:12px 18px;">${escapeHtml(params.actionLabel)}</a></p>
          <p style="margin:0 0 16px;line-height:1.65;color:#334155;word-break:break-word;">If the button does not open, copy and paste this link:<br><a href="${escapeHtml(params.actionUrl)}" style="color:#0f766e;">${escapeHtml(params.actionUrl)}</a></p>
          ${params.expiryText ? `<p style="margin:0 0 16px;line-height:1.65;color:#334155;">This link expires ${escapeHtml(params.expiryText)}.</p>` : ""}
          ${params.extraText ? `<p style="margin:0 0 16px;line-height:1.65;color:#334155;">${escapeHtml(params.extraText)}</p>` : ""}
          <p style="margin:0 0 16px;line-height:1.65;color:#475569;">${escapeHtml(reason)}</p>
          <p style="margin:0;line-height:1.65;color:#475569;">If you were not expecting this, you can ignore this email.</p>
          ${mscqrFooterHtml()}
        </div>
      </div>
    </div>
  `;

  return { text, html };
};

export const renderOtpEmail = (params: { code: string; expiresMinutes: number }) => {
  const text = appendMscqrIdentityToText(
    `Your MSCQR sign-in code is ${params.code}.\n\nThis one-time code expires in ${params.expiresMinutes} minutes.\n\nUse it only on ${MSCQR_URL}. We will never ask for this code by phone or chat.\n\nIf you did not request this code, you can ignore this email.`
  );
  const html = `
    <div style="margin:0;padding:0;background:#f8fafc;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
      <div style="max-width:560px;margin:0 auto;padding:28px 18px;">
        <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
          <p style="margin:0 0 12px;color:#0f766e;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;font-size:12px;">MSCQR verification</p>
          <h1 style="margin:0 0 16px;font-size:22px;line-height:1.25;">Your sign-in code</h1>
          <p style="font-size:28px;letter-spacing:0.16em;font-weight:700;margin:0 0 18px;color:#0f172a;">${escapeHtml(params.code)}</p>
          <p style="margin:0 0 16px;line-height:1.65;color:#334155;">This one-time code expires in ${params.expiresMinutes} minutes. Use it only on <a href="${MSCQR_URL}" style="color:#0f766e;">${MSCQR_URL}</a>.</p>
          <p style="margin:0;line-height:1.65;color:#475569;">If you did not request this code, you can ignore this email.</p>
          ${mscqrFooterHtml()}
        </div>
      </div>
    </div>
  `;
  return { text, html };
};

export const renderDiagnosticEmail = (params: {
  traceId: string;
  timestamp: string;
  intendedRecipient: string;
  fromAddress: string;
  smtpHost: string | null;
  smtpPort: number | null;
  smtpSecure: boolean | null;
  messageId?: string | null;
}) => {
  const text = appendMscqrIdentityToText(
    `MSCQR SMTP diagnostic\n\nTrace ID: ${params.traceId}\nUTC timestamp: ${params.timestamp}\nIntended recipient: ${params.intendedRecipient}\nFrom address: ${params.fromAddress}\nSMTP host: ${params.smtpHost || "not configured"}\nSMTP port: ${params.smtpPort || "not configured"}\nSMTP secure: ${params.smtpSecure === null ? "not configured" : String(params.smtpSecure)}\nMessage ID: ${params.messageId || "available after provider acceptance"}\n\nSearch Gmail with: in:anywhere "${params.traceId}"\n\nThis diagnostic confirms SMTP provider acceptance only. Inbox placement still depends on SPF, DKIM, DMARC, sender reputation, and recipient filtering.`
  );
  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;color:#0f172a;line-height:1.6;">
      <h1 style="font-size:20px;">MSCQR SMTP diagnostic</h1>
      <p><strong>Trace ID:</strong> ${escapeHtml(params.traceId)}</p>
      <p><strong>UTC timestamp:</strong> ${escapeHtml(params.timestamp)}</p>
      <p><strong>Intended recipient:</strong> ${escapeHtml(params.intendedRecipient)}</p>
      <p><strong>From address:</strong> ${escapeHtml(params.fromAddress)}</p>
      <p><strong>SMTP:</strong> ${escapeHtml(params.smtpHost || "not configured")}:${escapeHtml(params.smtpPort || "not configured")} secure=${escapeHtml(params.smtpSecure === null ? "not configured" : String(params.smtpSecure))}</p>
      <p>Search Gmail with: <code>in:anywhere "${escapeHtml(params.traceId)}"</code></p>
      <p>This diagnostic confirms SMTP provider acceptance only. Inbox placement still depends on SPF, DKIM, DMARC, sender reputation, and recipient filtering.</p>
      ${mscqrFooterHtml()}
    </div>
  `;
  return { text, html };
};
