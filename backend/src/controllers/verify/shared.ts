import { IncidentActorType, OwnershipTransferStatus, Prisma, QRStatus } from "@prisma/client";

import prisma from "../../config/database";
import {
  createCustomerOtpChallenge,
  issueCustomerVerifyToken,
  maskEmail,
  verifyCustomerOtpChallenge,
} from "../../services/customerVerifyAuthService";
import { getSuperadminAlertEmails } from "../../services/incidentEmailService";
import { createIncidentFromReport } from "../../services/incidentService";
import { resolveDuplicateRiskProfile } from "../../services/governanceService";
import { verifyCaptchaToken } from "../../services/captchaService";
import { enforceIncidentRateLimit } from "../../services/incidentRateLimitService";
import { hashIp, hashToken, randomOpaqueToken } from "../../utils/security";
import { deriveRequestDeviceFingerprint } from "../../utils/requestFingerprint";

export * from "./verifySchemas";
export * from "./verifyOwnership";
export * from "./verifyPresentation";
export { buildFraudVerificationSnapshot } from "./verifyFraudSnapshot";
export { createOwnershipTransferView as buildOwnershipTransferView } from "./verifyOwnership";

export {
  IncidentActorType,
  OwnershipTransferStatus,
  Prisma,
  QRStatus,
  createCustomerOtpChallenge,
  createIncidentFromReport,
  deriveRequestDeviceFingerprint,
  enforceIncidentRateLimit,
  getSuperadminAlertEmails,
  hashIp,
  hashToken,
  issueCustomerVerifyToken,
  maskEmail,
  prisma,
  randomOpaqueToken,
  resolveDuplicateRiskProfile,
  verifyCaptchaToken,
  verifyCustomerOtpChallenge,
};
