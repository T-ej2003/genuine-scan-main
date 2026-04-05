type WebAuthnCredentialTransport = "ble" | "hybrid" | "internal" | "nfc" | "smart-card" | "usb";

export type AdminWebAuthnCredentialSummary = {
  id: string;
  label: string;
  transports?: string[];
  lastUsedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};

export type WebAuthnCredentialSummary = AdminWebAuthnCredentialSummary;

export type WebAuthnRegistrationOptionsResponse = {
  ticket: string;
  options: {
    rp: {
      name: string;
      id: string;
    };
    user: {
      id: string;
      name: string;
      displayName: string;
    };
    challenge: string;
    timeout?: number;
    attestation?: AttestationConveyancePreference;
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    excludeCredentials?: Array<{
      id: string;
      type: PublicKeyCredentialType;
    }>;
  };
  expiresAt: string;
};

export type WebAuthnAuthenticationOptionsResponse = {
  ticket: string;
  options: {
    challenge: string;
    timeout?: number;
    rpId: string;
    userVerification?: UserVerificationRequirement;
    allowCredentials?: Array<{
      id: string;
      type: PublicKeyCredentialType;
      transports?: string[];
    }>;
  };
  expiresAt: string;
};

const toBase64Url = (value: ArrayBuffer | Uint8Array) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const fromBase64Url = (value: string) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
};

const requireWebAuthnSupport = () => {
  if (typeof window === "undefined" || typeof navigator === "undefined") {
    throw new Error("WebAuthn is only available in a browser session.");
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("This browser does not support WebAuthn security keys.");
  }
};

export const isWebAuthnSupported = () =>
  typeof window !== "undefined" && Boolean(window.PublicKeyCredential) && Boolean(navigator.credentials);

export const startAdminWebAuthnRegistration = async (
  payload: WebAuthnRegistrationOptionsResponse,
  label?: string | null
) => {
  requireWebAuthnSupport();

  const credential = (await navigator.credentials.create({
    publicKey: {
      ...payload.options,
      challenge: fromBase64Url(payload.options.challenge),
      user: {
        ...payload.options.user,
        id: fromBase64Url(payload.options.user.id),
      },
      excludeCredentials: (payload.options.excludeCredentials || []).map((entry) => ({
        ...entry,
        id: fromBase64Url(entry.id),
      })),
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("WebAuthn registration was cancelled.");
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey?.();
  const authenticatorData = response.getAuthenticatorData?.();

  if (!publicKey || !authenticatorData) {
    throw new Error("This authenticator did not return a usable public key.");
  }

  const transports = response.getTransports?.() || [];

  return {
    ticket: payload.ticket,
    label: String(label || "").trim() || undefined,
    credential: {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: "public-key" as const,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        attestationObject: toBase64Url(response.attestationObject),
        authenticatorData: toBase64Url(authenticatorData),
        publicKey: toBase64Url(publicKey),
        publicKeyAlgorithm: response.getPublicKeyAlgorithm?.() ?? -7,
        transports: transports.filter(Boolean) as WebAuthnCredentialTransport[],
      },
    },
  };
};

export const startWebAuthnRegistration = startAdminWebAuthnRegistration;

export const startAdminWebAuthnAuthentication = async (payload: WebAuthnAuthenticationOptionsResponse) => {
  requireWebAuthnSupport();

  const credential = (await navigator.credentials.get({
    publicKey: {
      ...payload.options,
      challenge: fromBase64Url(payload.options.challenge),
      allowCredentials: (payload.options.allowCredentials || []).map((entry) => ({
        ...entry,
        id: fromBase64Url(entry.id),
        transports: (entry.transports || []).filter(Boolean) as AuthenticatorTransport[],
      })),
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("WebAuthn verification was cancelled.");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    ticket: payload.ticket,
    credential: {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: "public-key" as const,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        authenticatorData: toBase64Url(response.authenticatorData),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
      },
    },
  };
};

export const startWebAuthnAuthentication = startAdminWebAuthnAuthentication;
