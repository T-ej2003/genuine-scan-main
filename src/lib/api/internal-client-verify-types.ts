export type VerifyEntryMethod = "SIGNED_SCAN" | "MANUAL_CODE";
export type VerifyAuthState = "PENDING" | "VERIFIED";

export type CustomerVerifyIdentity = {
  userId: string;
  email: string;
  maskedEmail?: string | null;
  displayName?: string | null;
  authProvider?: "GOOGLE";
};

export type CustomerVerifyTokenResponse = {
  token?: string;
  customer: CustomerVerifyIdentity;
};

export type VerificationSessionResponse = {
  sessionId: string;
  decisionId: string;
  code?: string | null;
  maskedCode?: string | null;
  brandName?: string | null;
  entryMethod: VerifyEntryMethod;
  authState: VerifyAuthState;
  intakeCompleted: boolean;
  revealed: boolean;
  startedAt: string;
  revealAt?: string | null;
  proofTier?: string | null;
  proofSource?: string | null;
  labelState?: string | null;
  printTrustState?: string | null;
  challengeRequired?: boolean;
  challengeCompleted?: boolean;
  challengeCompletedBy?: string | null;
  verificationLocked?: boolean;
  proofBindingRequired?: boolean;
  proofBindingExpiresAt?: string | null;
  sessionProofToken?: string | null;
  intake?: Record<string, unknown> | null;
  verification?: Record<string, unknown> | null;
};

export type CustomerPasskeyCredentialSummary = {
  id: string;
  label: string;
  transports?: string[];
  lastUsedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};
