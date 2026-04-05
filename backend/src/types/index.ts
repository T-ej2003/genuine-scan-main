import { UserRole } from "@prisma/client";

export type AuthSessionStage = "ACTIVE" | "MFA_BOOTSTRAP";
export type AuthAssuranceLevel = "PASSWORD" | "ADMIN_MFA";
export type StepUpMethod = "ADMIN_MFA" | "PASSWORD_REAUTH";

export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  linkedLicenseeIds?: string[] | null;
  sessionStage: "ACTIVE";
  authAssurance: AuthAssuranceLevel;
  authenticatedAt?: string | null;
  mfaVerifiedAt?: string | null;
}

export interface MfaBootstrapPayload {
  userId: string;
  email: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  linkedLicenseeIds?: string[] | null;
  stage: "MFA_BOOTSTRAP";
}

export interface AuthenticatedSessionClaims {
  userId: string;
  email: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  linkedLicenseeIds?: string[] | null;
  sessionStage: AuthSessionStage;
  authAssurance: AuthAssuranceLevel;
  authenticatedAt?: string | null;
  mfaVerifiedAt?: string | null;
}

export interface AuthenticatedRequest extends Express.Request {
  user?: AuthenticatedSessionClaims;
}

export interface CreateLicenseeDTO {
  name: string;
  prefix: string;
  description?: string;
}

export interface AllocateQRRangeDTO {
  licenseeId: string;
  startNumber: number;
  endNumber: number;
}

export interface CreateBatchDTO {
  name: string;
  startNumber: number;
  endNumber: number;
}

export interface AssignManufacturerDTO {
  manufacturerId: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}
