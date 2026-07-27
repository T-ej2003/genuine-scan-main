import { UserRole } from "@prisma/client";
import { hashPassword } from "./passwordService";
import { newCsrfToken } from "./tokenService";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { sendAuthEmail } from "./authEmailService";
import { maskEmailForLog } from "../mailTransportService";
import { mscqrBrandHeaderHtml, renderActionEmail } from "../emailTemplateService";
import { normalizeEmailAddress } from "../../utils/email";
import { isManufacturerRole } from "../manufacturerScopeService";
import { buildConnectorDownloadUrls } from "../connectorReleaseService";
import { prepareInvitation } from "../../rls-waves/session-b/b01/invitationRepository";
import {
  consumeInvitationBoundary,
  lookupInvitationBoundary,
} from "../../rls-waves/session-b/b01/preAuthRepository";

const addHours = (d: Date, hours: number) => new Date(d.getTime() + hours * 60 * 60 * 1000);

export const normalizeInviteRole = (role: string): UserRole => {
  const r = String(role || "").trim().toUpperCase();
  if (r === "SUPER_ADMIN") return UserRole.SUPER_ADMIN;
  if (r === "PLATFORM_SUPER_ADMIN") return UserRole.PLATFORM_SUPER_ADMIN;
  if (r === "LICENSEE_ADMIN") return UserRole.LICENSEE_ADMIN;
  if (r === "MANUFACTURER" || r === "MANUFACTURER_ADMIN") return UserRole.MANUFACTURER_ADMIN;

  throw new Error("Unsupported role");
};

const defaultNameForEmail = (email: string) => {
  const local = String(email.split("@")[0] || "").trim();
  if (!local) return "Invited user";
  return local.slice(0, 80);
};

const resolveWebAppBaseUrl = () => {
  const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
  if (cors) return cors.replace(/\/+$/, "");
  return "http://localhost:8080";
};

type InviteActorContext = {
  userId: string | null;
  email: string | null;
  displayName: string | null;
};

const displayActor = (actor: InviteActorContext | null) => {
  if (!actor) return null;
  return actor.displayName || actor.email || null;
};


const buildInviteIntro = (params: {
  isManufacturerInvite: boolean;
  actor: InviteActorContext | null;
  workspaceName?: string | null;
}) => {
  const actorLabel = displayActor(params.actor);
  const workspace = String(params.workspaceName || "").trim();
  const targetContext = workspace ? `${workspace} on MSCQR` : "MSCQR";

  if (actorLabel) {
    return params.isManufacturerInvite
      ? `You were invited by ${actorLabel} to join ${targetContext} as a manufacturer admin for printing and product verification.`
      : `You were invited by ${actorLabel} to join ${targetContext} for secure product verification.`;
  }

  return params.isManufacturerInvite
    ? "A brand workspace has invited you to activate a manufacturer account for MSCQR printing and product verification."
    : "You have been invited to activate an MSCQR account for secure product verification.";
};

const inviteHtmlTemplate = (params: {
  acceptUrl: string;
  connectorUrl: string | null;
  connectorDownloads:
    | {
        macos: { label: string; downloadUrl: string } | null;
        windows: { label: string; downloadUrl: string } | null;
      }
    | null;
  role: UserRole;
  expiresLabel: string;
}) => {
  const isManufacturerInvite = isManufacturerRole(params.role);
  const connectorDownloads = params.connectorDownloads;

  return `
    <div style="background:#eef2f7;padding:24px 0;font-family:Inter,Segoe UI,Arial,sans-serif;color:#10253f;">
      <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #d8e2ef;border-radius:24px;overflow:hidden;box-shadow:0 24px 60px rgba(15,23,42,0.08);">
        <div style="padding:28px 32px;background:linear-gradient(135deg,#10253f 0%,#17385b 100%);color:#ffffff;">
	          ${mscqrBrandHeaderHtml("onboarding", { inverse: true })}
          <h1 style="margin:12px 0 8px;font-size:30px;line-height:1.15;">Activate your MSCQR account</h1>
          <p style="margin:0;color:rgba(255,255,255,0.82);line-height:1.6;">Set your password, then follow the guided printing setup for your workstation if you are printing from the factory floor.</p>
        </div>
        <div style="padding:28px 32px;">
          <p style="margin:0 0 16px;line-height:1.7;">Use the secure activation button below. This invite expires in <strong>${params.expiresLabel}</strong>.</p>
          <div style="margin:0 0 22px;">
            <a href="${params.acceptUrl}" style="display:inline-block;padding:14px 22px;border-radius:999px;background:#10b981;color:#ffffff;text-decoration:none;font-weight:700;">Activate account</a>
          </div>
          ${
            isManufacturerInvite
              ? `
                <div style="border:1px solid #b7e4d1;background:#f2fcf7;border-radius:20px;padding:18px 18px 8px;margin-bottom:18px;">
                  <div style="font-size:18px;font-weight:800;margin-bottom:6px;color:#166534;">Install MSCQR Connector on the printing computer</div>
                  <p style="margin:0 0 12px;line-height:1.6;color:#24554a;">Download the connector on the Mac or Windows computer that is physically connected to the printer. Install once and it will start automatically every time that user signs in.</p>
                  ${
                    params.connectorUrl
                      ? `<div style="margin:0 0 12px;"><a href="${params.connectorUrl}" style="display:inline-block;padding:12px 18px;border-radius:999px;background:#ffffff;color:#10253f;text-decoration:none;font-weight:700;border:1px solid #c6d7eb;">Open connector download page</a></div>`
                      : ""
                  }
                  <ul style="margin:0 0 10px;padding-left:18px;line-height:1.8;color:#24554a;">
                    <li>Choose the installer that matches that computer: Mac or Windows.</li>
                    <li>Run the installer once.</li>
                    <li>Open MSCQR and use Printer Setup to confirm the printer shows as ready.</li>
                  </ul>
                  ${
                    connectorDownloads
                      ? `<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
                          ${
                            connectorDownloads.macos
                              ? `<a href="${connectorDownloads.macos.downloadUrl}" style="display:inline-block;padding:10px 16px;border-radius:999px;background:#10253f;color:#ffffff;text-decoration:none;font-weight:700;">Download for Mac</a>`
                              : ""
                          }
                          ${
                            connectorDownloads.windows
                              ? `<a href="${connectorDownloads.windows.downloadUrl}" style="display:inline-block;padding:10px 16px;border-radius:999px;background:#ffffff;color:#10253f;text-decoration:none;font-weight:700;border:1px solid #c6d7eb;">Download for Windows</a>`
                              : ""
                          }
                        </div>`
                      : ""
                  }
                </div>
              `
              : ""
          }
          <p style="margin:0;color:#5f7287;line-height:1.7;">If you were not expecting this email, you can safely ignore it.</p>
        </div>
      </div>
    </div>
  `;
};

export const createInvite = async (input: {
  email?: string | null;
  role: string;
  name?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  allowExistingInvitedUser?: boolean;
  requireExistingUser?: boolean;
  createdByUserId: string;
  ipHash: string | null;
  userAgent: string | null;
  actorSessionId?: string | null;
  databaseCapability: string;
  requestId: string;
  actorRole: UserRole;
}) => {
  const allowExistingInvitedUser = Boolean(input.allowExistingInvitedUser);
  const requireExistingUser = Boolean(input.requireExistingUser);
  const email = input.email == null ? null : normalizeEmailAddress(input.email);
  if (!email && !requireExistingUser) throw new Error("Invalid email address");

  const role = normalizeInviteRole(input.role);

  const licenseeId = input.licenseeId ? String(input.licenseeId).trim() : null;
  const manufacturerId = input.manufacturerId ? String(input.manufacturerId).trim() : null;

  const now = new Date();
  const expiresAt = addHours(now, 24);
  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  const userName = String(input.name || "").trim() || (email ? defaultNameForEmail(email) : "Invited user");
  const createdByUserId = String(input.createdByUserId || "").trim();
  if (!createdByUserId) throw new Error("INVITE_ACTOR_REQUIRED");

  const actorSessionId = String(input.actorSessionId || "").trim();
  if (!actorSessionId) throw new Error("INVITE_ACTOR_SESSION_REQUIRED");
  const result = await prepareInvitation({
    capability: input.databaseCapability,
    actorUserId: createdByUserId,
    requestId: input.requestId,
    purpose: requireExistingUser ? "licensee-admin-invite-resend" : "auth-invite-create",
    actorRole: input.actorRole,
    actorLicenseeId: input.actorRole === UserRole.LICENSEE_ADMIN ? licenseeId : null,
    requestedEmail: email,
    requestedName: userName,
    requestedRole: role,
    requestedLicenseeId: licenseeId,
    requestedManufacturerId: manufacturerId,
    allowExistingInvitedUser,
    requireExistingUser,
    tokenHash,
    createdAt: now,
    expiresAt,
    actorSessionId,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });

  if (result.linkAction && !result.inviteId) {
    return {
      inviteId: null,
      expiresAt: null,
      email: maskEmailForLog(result.inviteEmail),
      role,
      inviteLink: null,
      emailSent: false,
      emailDelivered: false,
      emailAttempted: false,
      emailErrorCode: null,
      emailDiagnostic: "Invite was linked to an existing manufacturer account; no email was sent.",
      deliveryError: null,
      providerMessageId: null,
      providerResponseCode: null,
      providerResponse: null,
      acceptedRecipients: [],
      rejectedRecipients: [],
      pendingRecipients: [],
      linkAction: result.linkAction,
      user: {
        id: result.userId,
        email: result.userEmail,
        name: result.userName,
        role: result.userRole,
        licenseeId: result.userLicenseeId,
        orgId: result.userOrganizationId,
        status: result.userStatus,
      },
      csrfToken: newCsrfToken(),
    };
  }

  if (!result.inviteId || !result.inviteExpiresAt) {
    throw new Error("app_rls.prepare_invitation returned an incomplete invitation");
  }

  // Send email outside the transaction (delivery should not block DB state).
  const baseUrl = resolveWebAppBaseUrl();
  const acceptUrl = `${baseUrl}/accept-invite?token=${encodeURIComponent(rawToken)}`;
  const connectorLandingUrl = isManufacturerRole(role)
    ? `${baseUrl}/connector-download?inviteToken=${encodeURIComponent(rawToken)}`
    : null;
  const connectorDistribution = isManufacturerRole(role) ? buildConnectorDownloadUrls(baseUrl) : null;

  const isManufacturerInvite = isManufacturerRole(role);
  const inviteActor: InviteActorContext = {
    userId: result.actorUserId,
    email: result.actorEmail,
    displayName: result.actorDisplayName,
  };
  const subject = isManufacturerInvite ? "Set up your MSCQR manufacturer account" : "Activate your MSCQR account";
  const emailBody = renderActionEmail({
    heading: subject,
    intro: buildInviteIntro({
      isManufacturerInvite,
      actor: inviteActor,
      workspaceName: result.licenseeName,
    }),
    actionLabel: "Activate account",
    actionUrl: acceptUrl,
    expiryText: "in 24 hours",
    workspaceName: result.licenseeName,
    invitedByDisplay: inviteActor.displayName,
    invitedByEmail: inviteActor.email,
    replyToNotice: Boolean(inviteActor.email),
    reason: inviteActor.email
      ? "An MSCQR administrator created this invite for your email address. Replying to this email will contact the inviting admin when available."
      : "An MSCQR administrator created this invite for your email address.",
    extraText: isManufacturerInvite && connectorLandingUrl
      ? `After activating your account, install MSCQR Connector on the computer connected to the printer: ${connectorLandingUrl}`
      : null,
  });

  const delivery = await sendAuthEmail({
    toAddress: result.inviteEmail,
    subject,
    text: emailBody.text,
    html: emailBody.html,
    template: "invite",
    orgId: result.userOrganizationId,
    licenseeId: result.userLicenseeId,
    actorUserId: result.actorUserId,
    actorEmail: inviteActor.email,
    actorDisplayName: inviteActor.displayName,
    replyToMode: "actor",
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });

  return {
    inviteId: result.inviteId,
    expiresAt: result.inviteExpiresAt,
    email: result.inviteEmail,
    role: result.inviteRole,
    inviteLink: acceptUrl,
    connectorDownloadUrl: connectorLandingUrl,
    connectorDownloads: connectorDistribution?.downloads || null,
    emailSent: delivery.delivered,
    emailDelivered: delivery.delivered,
    emailAttempted: delivery.attempted,
    emailErrorCode: delivery.errorCode || delivery.error || null,
    emailDiagnostic: delivery.diagnostic || null,
    deliveryError: delivery.errorCode || delivery.error || null,
    providerMessageId: delivery.providerMessageId || null,
    providerResponseCode: delivery.providerResponseCode || null,
    providerResponse: null,
    usedFrom: delivery.usedFrom || null,
    replyTo: delivery.replyTo || null,
    actorEmail: inviteActor.email,
    actorUserId: inviteActor.userId,
    acceptedRecipients: delivery.acceptedRecipients || [],
    rejectedRecipients: delivery.rejectedRecipients || [],
    pendingRecipients: delivery.pendingRecipients || [],
    linkAction: result.linkAction,
    user: {
      id: result.userId,
      email: result.userEmail,
      name: result.userName,
      role: result.userRole,
      licenseeId: result.userLicenseeId,
      orgId: result.userOrganizationId,
      status: result.userStatus,
    },
    csrfToken: newCsrfToken(),
  };
};

export const acceptInvite = async (input: {
  rawToken: string;
  password: string;
  name?: string | null;
  requestId: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const now = new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);
  const passwordHash = await hashPassword(input.password);
  const result = await consumeInvitationBoundary({
    tokenHashCandidates,
    passwordHash,
    requestedName: String(input.name || "").trim() || null,
    consumedAt: now,
    requestId: input.requestId,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });
  if (!result) throw new Error("Invalid or expired invite token");

  return result;
};

export const getInvitePreview = async (rawToken: string) => {
  const now = new Date();
  const tokenHashCandidates = buildTokenHashCandidates(rawToken);

  const invite = await lookupInvitationBoundary({ tokenHashCandidates, checkedAt: now });
  if (!invite) throw new Error("Invalid or expired invite token");

  return {
    email: invite.email,
    role: invite.role,
    expiresAt: invite.expiresAt,
    licenseeName: invite.licenseeName,
    requiresConnector: invite.requiresConnector,
  };
};
