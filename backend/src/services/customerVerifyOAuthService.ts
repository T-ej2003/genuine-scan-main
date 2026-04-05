import { createHash } from "crypto";
import jwt from "jsonwebtoken";
import type { Request } from "express";

import {
  CustomerVerifyAuthProvider,
  CustomerVerifyIdentity,
  deriveCustomerVerifyUserId,
  issueCustomerVerifyToken,
  maskEmail,
  normalizeCustomerVerifyEmail,
} from "./customerVerifyAuthService";
import { getJwtSecret, randomOpaqueToken } from "../utils/security";

export type CustomerOAuthProvider = "google";

type ProviderConfig = {
  id: CustomerOAuthProvider;
  label: string;
  clientId: string;
  clientSecret?: string;
};

type OAuthStatePayload = {
  type: "customer_verify_oauth_state";
  provider: CustomerOAuthProvider;
  returnTo: string;
  codeVerifier?: string | null;
};

type OAuthExchangePayload = {
  type: "customer_verify_oauth_exchange";
  provider: CustomerOAuthProvider;
  email: string;
  displayName?: string | null;
};

type CustomerOAuthProfile = {
  provider: CustomerOAuthProvider;
  email: string;
  displayName?: string | null;
  authProvider: CustomerVerifyAuthProvider;
};

const OAUTH_STATE_TTL_MINUTES = 15;
const OAUTH_EXCHANGE_TTL_MINUTES = 10;

const normalizeBaseUrl = (value?: string | null) => String(value || "").trim().replace(/\/+$/, "");

const getOauthStateSecret = () => String(process.env.CUSTOMER_VERIFY_OAUTH_STATE_SECRET || process.env.CUSTOMER_VERIFY_TOKEN_SECRET || getJwtSecret()).trim();
const getOauthExchangeSecret = () => String(process.env.CUSTOMER_VERIFY_OAUTH_EXCHANGE_SECRET || process.env.CUSTOMER_VERIFY_TOKEN_SECRET || getJwtSecret()).trim();

const toBase64Url = (value: Buffer | string) => Buffer.from(value).toString("base64url");
const sha256Base64Url = (value: string) => toBase64Url(createHash("sha256").update(value).digest());

const tryParseUrl = (value: string) => {
  try {
    return new URL(value);
  } catch {
    return null;
  }
};

const resolveApiBaseUrl = (req: Request) => {
  const explicitApi = normalizeBaseUrl(process.env.PUBLIC_API_BASE_URL);
  if (explicitApi) return explicitApi;

  const origin = req.get("origin");
  if (origin) return normalizeBaseUrl(origin);

  const forwardedProto = String(req.get("x-forwarded-proto") || "").trim();
  const protocol = forwardedProto || req.protocol;
  return `${protocol}://${req.get("host") || "localhost"}`;
};

const deriveAllowedFrontendOrigins = () => {
  const origins = [
    String(process.env.APP_URL || "").trim(),
    String(process.env.PUBLIC_APP_URL || "").trim(),
    String(process.env.FRONTEND_URL || "").trim(),
  ]
    .map((value) => {
      const parsed = tryParseUrl(value);
      return parsed?.origin || "";
    })
    .filter(Boolean);

  return Array.from(new Set(origins));
};

const validateReturnTo = (raw: string) => {
  const parsed = tryParseUrl(raw);
  if (!parsed) {
    throw new Error("Invalid return URL");
  }

  const allowedOrigins = deriveAllowedFrontendOrigins();
  if (allowedOrigins.length && !allowedOrigins.includes(parsed.origin)) {
    throw new Error("Return URL origin is not allowed");
  }

  if (!parsed.pathname.startsWith("/verify") && !parsed.pathname.startsWith("/scan")) {
    throw new Error("Return URL must stay inside the verify flow");
  }

  return parsed.toString();
};

const appendHashParam = (input: string, key: string, value: string) => {
  const url = new URL(input);
  const params = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  params.set(key, value);
  url.hash = params.toString();
  return url.toString();
};

const getGoogleConfig = (): ProviderConfig | null => {
  const clientId = String(process.env.CUSTOMER_VERIFY_GOOGLE_CLIENT_ID || "").trim();
  const clientSecret = String(process.env.CUSTOMER_VERIFY_GOOGLE_CLIENT_SECRET || "").trim();
  if (!clientId || !clientSecret) return null;
  return { id: "google", label: "Google", clientId, clientSecret };
};

const loadProviderConfig = (provider: CustomerOAuthProvider): ProviderConfig | null => {
  switch (provider) {
    case "google":
      return getGoogleConfig();
    default:
      return null;
  }
};

export const listConfiguredCustomerOAuthProviders = () =>
  (["google"] as const)
    .map((provider) => loadProviderConfig(provider))
    .filter(Boolean)
    .map((config) => ({ id: config!.id, label: config!.label }));

const issueOauthState = (payload: OAuthStatePayload) =>
  jwt.sign(payload, getOauthStateSecret(), { expiresIn: `${OAUTH_STATE_TTL_MINUTES}m` });

const verifyOauthState = (token: string): OAuthStatePayload => {
  const decoded = jwt.verify(String(token || "").trim(), getOauthStateSecret()) as OAuthStatePayload;
  if (!decoded || decoded.type !== "customer_verify_oauth_state") {
    throw new Error("Invalid OAuth state");
  }
  return decoded;
};

const issueOauthExchangeTicket = (profile: CustomerOAuthProfile) =>
  jwt.sign(
    {
      type: "customer_verify_oauth_exchange",
      provider: profile.provider,
      email: profile.email,
      displayName: profile.displayName || null,
    } satisfies OAuthExchangePayload,
    getOauthExchangeSecret(),
    { expiresIn: `${OAUTH_EXCHANGE_TTL_MINUTES}m` }
  );

const verifyOauthExchangeTicket = (token: string): OAuthExchangePayload => {
  const decoded = jwt.verify(String(token || "").trim(), getOauthExchangeSecret()) as OAuthExchangePayload;
  if (!decoded || decoded.type !== "customer_verify_oauth_exchange") {
    throw new Error("Invalid OAuth exchange ticket");
  }
  return decoded;
};

const buildCustomerIdentityFromProfile = (profile: CustomerOAuthProfile): CustomerVerifyIdentity => {
  const normalizedEmail = normalizeCustomerVerifyEmail(profile.email);
  return {
    userId: deriveCustomerVerifyUserId(normalizedEmail),
    email: normalizedEmail,
    authStrength: "SOCIAL",
    authProvider: profile.authProvider,
    displayName: profile.displayName || null,
  };
};

const buildGoogleAuthorizationUrl = (params: {
  config: ProviderConfig;
  callbackUrl: string;
  stateToken: string;
  codeVerifier: string;
}) => {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", params.config.clientId);
  url.searchParams.set("redirect_uri", params.callbackUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", params.stateToken);
  url.searchParams.set("code_challenge", sha256Base64Url(params.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("prompt", "select_account");
  return url.toString();
};

const postForm = async (url: string, body: URLSearchParams, headers?: Record<string, string>) => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(headers || {}),
    },
    body: body.toString(),
  });
  const payload = (await response.json().catch(() => null)) as Record<string, any> | null;
  if (!response.ok || !payload) {
    const message = String(payload?.error_description || payload?.error || `OAuth token exchange failed (${response.status})`).trim();
    throw new Error(message);
  }
  return payload;
};

const fetchJson = async (url: string, headers?: Record<string, string>) => {
  const response = await fetch(url, {
    method: "GET",
    headers: headers || {},
  });
  const payload = (await response.json().catch(() => null)) as Record<string, any> | null;
  if (!response.ok || !payload) {
    throw new Error(`OAuth profile lookup failed (${response.status})`);
  }
  return payload;
};

const exchangeGoogleCode = async (params: {
  config: ProviderConfig;
  code: string;
  callbackUrl: string;
  codeVerifier: string;
}): Promise<CustomerOAuthProfile> => {
  const tokenPayload = await postForm(
    "https://oauth2.googleapis.com/token",
    new URLSearchParams({
      client_id: params.config.clientId,
      client_secret: params.config.clientSecret || "",
      code: params.code,
      code_verifier: params.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: params.callbackUrl,
    })
  );

  const accessToken = String(tokenPayload.access_token || "").trim();
  if (!accessToken) throw new Error("Google OAuth did not return an access token");

  const userInfo = await fetchJson("https://openidconnect.googleapis.com/v1/userinfo", {
    Authorization: `Bearer ${accessToken}`,
  });

  const email = normalizeCustomerVerifyEmail(String(userInfo.email || "").trim());
  const emailVerified = Boolean(userInfo.email_verified);
  if (!email || !emailVerified) {
    throw new Error("Google account must provide a verified email address");
  }

  return {
    provider: "google",
    email,
    displayName: String(userInfo.name || userInfo.given_name || email).trim() || email,
    authProvider: "GOOGLE",
  };
};

export const buildCustomerOAuthAuthorizationUrl = (params: {
  provider: CustomerOAuthProvider;
  returnTo: string;
  req: Request;
}) => {
  const config = loadProviderConfig(params.provider);
  if (!config) {
    throw new Error("That customer identity provider is not configured");
  }

  const returnTo = validateReturnTo(params.returnTo);
  const callbackUrl = `${resolveApiBaseUrl(params.req)}/api/verify/auth/oauth/${params.provider}/callback`;

  const codeVerifier = randomOpaqueToken(32);
  const state = issueOauthState({
    type: "customer_verify_oauth_state",
    provider: "google",
    returnTo,
    codeVerifier,
  });
  return buildGoogleAuthorizationUrl({ config, callbackUrl, stateToken: state, codeVerifier });
};

export const finishCustomerOAuthCallback = async (params: {
  provider: CustomerOAuthProvider;
  code?: string | null;
  state?: string | null;
  error?: string | null;
  req: Request;
}) => {
  if (params.error) {
    const state = params.state ? verifyOauthState(params.state) : null;
    const returnTo = state?.returnTo || deriveAllowedFrontendOrigins()[0] || String(process.env.APP_URL || "").trim() || "http://localhost:8080/verify";
    return appendHashParam(returnTo, "customer_auth_error", String(params.error));
  }

  if (!params.code || !params.state) {
    throw new Error("Missing OAuth callback parameters");
  }

  const state = verifyOauthState(params.state);
  if (state.provider !== params.provider) {
    throw new Error("OAuth provider mismatch");
  }

  const config = loadProviderConfig(params.provider);
  if (!config) {
    throw new Error("That customer identity provider is not configured");
  }

  const callbackUrl = `${resolveApiBaseUrl(params.req)}/api/verify/auth/oauth/${params.provider}/callback`;
  let profile: CustomerOAuthProfile;

  profile = await exchangeGoogleCode({
    config,
    code: params.code,
    callbackUrl,
    codeVerifier: String(state.codeVerifier || "").trim(),
  });

  const exchangeTicket = issueOauthExchangeTicket(profile);
  return appendHashParam(state.returnTo, "customer_auth_exchange", exchangeTicket);
};

export const exchangeCustomerOAuthTicketForSession = (ticket: string) => {
  const decoded = verifyOauthExchangeTicket(ticket);
  const authProvider: CustomerVerifyAuthProvider = "GOOGLE";
  const identity = buildCustomerIdentityFromProfile({
    provider: decoded.provider,
    email: decoded.email,
    displayName: decoded.displayName || null,
    authProvider,
  });

  const token = issueCustomerVerifyToken(identity, {
    authStrength: "SOCIAL",
    authProvider,
    displayName: identity.displayName || null,
  });

  return {
    token,
    customer: {
      userId: identity.userId,
      email: identity.email,
      maskedEmail: maskEmail(identity.email),
      displayName: identity.displayName || null,
      authProvider,
    },
  };
};
