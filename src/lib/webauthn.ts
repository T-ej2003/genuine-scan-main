import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/browser";

export type AdminWebAuthnCredentialSummary = {
  id: string;
  label: string;
  transports?: string[];
  lastUsedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};

export type WebAuthnCredentialSummary = AdminWebAuthnCredentialSummary;

type JsonCredential<T> = T & Record<string, unknown>;

export type WebAuthnRegistrationOptionsResponse = {
  ticket: string;
  options: PublicKeyCredentialCreationOptionsJSON | Record<string, unknown>;
  expiresAt: string;
};

export type WebAuthnAuthenticationOptionsResponse = {
  ticket: string;
  options: PublicKeyCredentialRequestOptionsJSON | Record<string, unknown>;
  expiresAt: string;
};

const requireWebAuthnSupport = () => {
  if (!browserSupportsWebAuthn()) {
    throw new Error("This browser does not support security keys or passkeys.");
  }
};

export const isWebAuthnSupported = () => browserSupportsWebAuthn();

export const startAdminWebAuthnRegistration = async (
  payload: WebAuthnRegistrationOptionsResponse,
  label?: string | null
): Promise<{ ticket: string; label?: string; credential: JsonCredential<RegistrationResponseJSON> }> => {
  requireWebAuthnSupport();
  const credential = await startRegistration({ optionsJSON: payload.options as PublicKeyCredentialCreationOptionsJSON });
  return {
    ticket: payload.ticket,
    label: String(label || "").trim() || undefined,
    credential: credential as JsonCredential<RegistrationResponseJSON>,
  };
};

export const startWebAuthnRegistration = startAdminWebAuthnRegistration;

export const startAdminWebAuthnAuthentication = async (
  payload: WebAuthnAuthenticationOptionsResponse
): Promise<{ ticket: string; credential: JsonCredential<AuthenticationResponseJSON> }> => {
  requireWebAuthnSupport();
  const credential = await startAuthentication({ optionsJSON: payload.options as PublicKeyCredentialRequestOptionsJSON });
  return {
    ticket: payload.ticket,
    credential: credential as JsonCredential<AuthenticationResponseJSON>,
  };
};

export const startWebAuthnAuthentication = startAdminWebAuthnAuthentication;
