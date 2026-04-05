import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as cryptoSign, verify as cryptoVerify } from "crypto";
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

export type CustomerOAuthProvider = "google" | "apple" | "x";

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
  nonce?: string | null;
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
const X_LOCAL_EMAIL_DOMAIN = "customer-verify.local";
const X_API_BASES = ["https://api.x.com", "https://api.twitter.com"];

const normalizeBaseUrl = (value?: string | null) => String(value || "").trim().replace(/\/+$/, "");

const getOauthStateSecret = () => String(process.env.CUSTOMER_VERIFY_OAUTH_STATE_SECRET || process.env.CUSTOMER_VERIFY_TOKEN_SECRET || getJwtSecret()).trim();
const getOauthExchangeSecret = () => String(process.env.CUSTOMER_VERIFY_OAUTH_EXCHANGE_SECRET || process.env.CUSTOMER_VERIFY_TOKEN_SECRET || getJwtSecret()).trim();

const toBase64Url = (value: Buffer | string) => Buffer.from(value).toString("base64url");
const fromBase64Url = (value: string) => Buffer.from(String(value || "").trim(), "base64url");
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

const getAppleConfig = (): ProviderConfig | null => {
  const clientId = String(process.env.CUSTOMER_VERIFY_APPLE_CLIENT_ID || "").trim();
  const teamId = String(process.env.CUSTOMER_VERIFY_APPLE_TEAM_ID || "").trim();
  const keyId = String(process.env.CUSTOMER_VERIFY_APPLE_KEY_ID || "").trim();
  const privateKey = String(process.env.CUSTOMER_VERIFY_APPLE_PRIVATE_KEY || "").trim();
  if (!clientId || !teamId || !keyId || !privateKey) return null;
  return { id: "apple", label: "Apple", clientId };
};

const getXConfig = (): ProviderConfig | null => {
  const clientId = String(process.env.CUSTOMER_VERIFY_X_CLIENT_ID || "").trim();
  const clientSecret = String(process.env.CUSTOMER_VERIFY_X_CLIENT_SECRET || "").trim();
  if (!clientId || !clientSecret) return null;
  return { id: "x", label: "X", clientId, clientSecret };
};

const loadProviderConfig = (provider: CustomerOAuthProvider): ProviderConfig | null => {
  switch (provider) {
    case "google":
      return getGoogleConfig();
    case "apple":
      return getAppleConfig();
    case "x":
      return getXConfig();
    default:
      return null;
  }
};

export const listConfiguredCustomerOAuthProviders = () =>
  (["google", "apple", "x"] as const)
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

const buildAppleAuthorizationUrl = (params: {
  config: ProviderConfig;
  callbackUrl: string;
  stateToken: string;
  nonce: string;
}) => {
  const url = new URL("https://appleid.apple.com/auth/authorize");
  url.searchParams.set("client_id", params.config.clientId);
  url.searchParams.set("redirect_uri", params.callbackUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("response_mode", "query");
  url.searchParams.set("scope", "name email");
  url.searchParams.set("state", params.stateToken);
  url.searchParams.set("nonce", params.nonce);
  return url.toString();
};

const buildXAuthorizationUrl = (params: {
  config: ProviderConfig;
  callbackUrl: string;
  stateToken: string;
  codeVerifier: string;
}) => {
  const url = new URL("https://twitter.com/i/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", params.config.clientId);
  url.searchParams.set("redirect_uri", params.callbackUrl);
  url.searchParams.set("scope", "users.read tweet.read offline.access");
  url.searchParams.set("state", params.stateToken);
  url.searchParams.set("code_challenge", sha256Base64Url(params.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
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

const parseJwt = (token: string) => {
  const [header, payload, signature] = String(token || "").split(".");
  if (!header || !payload || !signature) throw new Error("Invalid JWT structure");
  return {
    header: JSON.parse(fromBase64Url(header).toString("utf8")) as Record<string, any>,
    payload: JSON.parse(fromBase64Url(payload).toString("utf8")) as Record<string, any>,
    signed: `${header}.${payload}`,
    signature: fromBase64Url(signature),
  };
};

const buildAppleClientSecret = (clientId: string) => {
  const teamId = String(process.env.CUSTOMER_VERIFY_APPLE_TEAM_ID || "").trim();
  const keyId = String(process.env.CUSTOMER_VERIFY_APPLE_KEY_ID || "").trim();
  const rawPrivateKey = String(process.env.CUSTOMER_VERIFY_APPLE_PRIVATE_KEY || "").trim();
  const privateKey = rawPrivateKey.replace(/\\n/g, "\n");
  const now = Math.floor(Date.now() / 1000);
  const header = toBase64Url(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JWT" }));
  const payload = toBase64Url(
    JSON.stringify({
      iss: teamId,
      iat: now,
      exp: now + 60 * 60 * 24 * 30,
      aud: "https://appleid.apple.com",
      sub: clientId,
    })
  );
  const signerInput = `${header}.${payload}`;
  const signature = cryptoSign("sha256", Buffer.from(signerInput), createPrivateKey(privateKey));
  return `${signerInput}.${toBase64Url(signature)}`;
};

const verifyAppleIdToken = async (params: { idToken: string; clientId: string; expectedNonce: string }) => {
  const parsed = parseJwt(params.idToken);
  const kid = String(parsed.header.kid || "").trim();
  const alg = String(parsed.header.alg || "").trim();
  if (!kid || alg !== "RS256") {
    throw new Error("Invalid Apple ID token header");
  }

  const keySet = await fetchJson("https://appleid.apple.com/auth/keys");
  const keys = Array.isArray(keySet.keys) ? keySet.keys : [];
  const jwk = keys.find((candidate: any) => String(candidate.kid || "").trim() === kid);
  if (!jwk) throw new Error("Apple signing key not found");

  const valid = cryptoVerify("RSA-SHA256", Buffer.from(parsed.signed), createPublicKey({ key: jwk, format: "jwk" as any }), parsed.signature);
  if (!valid) throw new Error("Invalid Apple ID token signature");

  const issuer = String(parsed.payload.iss || "").trim();
  const audience = String(parsed.payload.aud || "").trim();
  const nonce = String(parsed.payload.nonce || "").trim();
  const exp = Number(parsed.payload.exp || 0);
  if (issuer !== "https://appleid.apple.com" || audience !== params.clientId || !exp || exp * 1000 <= Date.now()) {
    throw new Error("Apple ID token claims are invalid");
  }
  if (params.expectedNonce && nonce && nonce !== params.expectedNonce) {
    throw new Error("Apple ID token nonce mismatch");
  }

  return parsed.payload;
};

const exchangeAppleCode = async (params: {
  config: ProviderConfig;
  code: string;
  callbackUrl: string;
  nonce: string;
}): Promise<CustomerOAuthProfile> => {
  const tokenPayload = await postForm(
    "https://appleid.apple.com/auth/token",
    new URLSearchParams({
      client_id: params.config.clientId,
      client_secret: buildAppleClientSecret(params.config.clientId),
      code: params.code,
      grant_type: "authorization_code",
      redirect_uri: params.callbackUrl,
    })
  );

  const idToken = String(tokenPayload.id_token || "").trim();
  if (!idToken) throw new Error("Apple OAuth did not return an ID token");

  const payload = await verifyAppleIdToken({
    idToken,
    clientId: params.config.clientId,
    expectedNonce: params.nonce,
  });

  const email = normalizeCustomerVerifyEmail(String(payload.email || "").trim());
  const emailVerified = String(payload.email_verified || "").trim().toLowerCase();
  if (!email || !["true", "1"].includes(emailVerified)) {
    throw new Error("Apple account must provide a verified email address");
  }

  return {
    provider: "apple",
    email,
    displayName: String(payload.email || email).trim() || email,
    authProvider: "APPLE",
  };
};

const exchangeXCode = async (params: {
  config: ProviderConfig;
  code: string;
  callbackUrl: string;
  codeVerifier: string;
}): Promise<CustomerOAuthProfile> => {
  const basic = Buffer.from(`${params.config.clientId}:${params.config.clientSecret || ""}`).toString("base64");
  let tokenPayload: Record<string, any> | null = null;
  let apiBase = X_API_BASES[0];

  for (const candidate of X_API_BASES) {
    try {
      tokenPayload = await postForm(
        `${candidate}/2/oauth2/token`,
        new URLSearchParams({
          client_id: params.config.clientId,
          code: params.code,
          code_verifier: params.codeVerifier,
          grant_type: "authorization_code",
          redirect_uri: params.callbackUrl,
        }),
        {
          Authorization: `Basic ${basic}`,
        }
      );
      apiBase = candidate;
      break;
    } catch (error) {
      if (candidate === X_API_BASES[X_API_BASES.length - 1]) throw error;
    }
  }

  if (!tokenPayload) {
    throw new Error("X OAuth token exchange failed");
  }

  const accessToken = String(tokenPayload.access_token || "").trim();
  if (!accessToken) throw new Error("X OAuth did not return an access token");

  const profile = await fetchJson(`${apiBase}/2/users/me?user.fields=id,name,username`, {
    Authorization: `Bearer ${accessToken}`,
  });
  const data = (profile.data || {}) as Record<string, any>;
  const subject = String(data.id || "").trim();
  const username = String(data.username || "").trim();
  if (!subject) throw new Error("X account lookup did not return a user id");

  const email = normalizeCustomerVerifyEmail(`${username || `x-${subject}`}@${X_LOCAL_EMAIL_DOMAIN}`);
  return {
    provider: "x",
    email,
    displayName: username ? `@${username}` : String(data.name || `X user ${subject}`).trim(),
    authProvider: "X",
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

  if (params.provider === "google") {
    const codeVerifier = randomOpaqueToken(32);
    const state = issueOauthState({
      type: "customer_verify_oauth_state",
      provider: "google",
      returnTo,
      codeVerifier,
    });
    return buildGoogleAuthorizationUrl({ config, callbackUrl, stateToken: state, codeVerifier });
  }

  if (params.provider === "apple") {
    const nonce = toBase64Url(randomBytes(18));
    const state = issueOauthState({
      type: "customer_verify_oauth_state",
      provider: "apple",
      returnTo,
      nonce,
    });
    return buildAppleAuthorizationUrl({ config, callbackUrl, stateToken: state, nonce });
  }

  const codeVerifier = randomOpaqueToken(32);
  const state = issueOauthState({
    type: "customer_verify_oauth_state",
    provider: "x",
    returnTo,
    codeVerifier,
  });
  return buildXAuthorizationUrl({ config, callbackUrl, stateToken: state, codeVerifier });
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

  if (params.provider === "google") {
    profile = await exchangeGoogleCode({
      config,
      code: params.code,
      callbackUrl,
      codeVerifier: String(state.codeVerifier || "").trim(),
    });
  } else if (params.provider === "apple") {
    profile = await exchangeAppleCode({
      config,
      code: params.code,
      callbackUrl,
      nonce: String(state.nonce || "").trim(),
    });
  } else {
    profile = await exchangeXCode({
      config,
      code: params.code,
      callbackUrl,
      codeVerifier: String(state.codeVerifier || "").trim(),
    });
  }

  const exchangeTicket = issueOauthExchangeTicket(profile);
  return appendHashParam(state.returnTo, "customer_auth_exchange", exchangeTicket);
};

export const exchangeCustomerOAuthTicketForSession = (ticket: string) => {
  const decoded = verifyOauthExchangeTicket(ticket);
  const authProvider: CustomerVerifyAuthProvider =
    decoded.provider === "google" ? "GOOGLE" : decoded.provider === "apple" ? "APPLE" : "X";
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
      maskedEmail: identity.email.includes(`@${X_LOCAL_EMAIL_DOMAIN}`) ? null : maskEmail(identity.email),
      displayName: identity.displayName || null,
      authProvider,
    },
  };
};

export const isSyntheticCustomerVerifyEmail = (value: string) =>
  normalizeCustomerVerifyEmail(value).endsWith(`@${X_LOCAL_EMAIL_DOMAIN}`);
