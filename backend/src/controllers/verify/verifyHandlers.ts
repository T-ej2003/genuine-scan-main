export { logoutCustomerVerifySession, requestCustomerEmailOtp, verifyCustomerEmailOtp } from "./authHandlers";
export {
  completeCustomerOAuth,
  exchangeCustomerOAuth,
  listCustomerOAuthProviders,
  startCustomerOAuth,
} from "./oauthHandlers";
export {
  beginCustomerPasskeyAssertion,
  beginCustomerPasskeyRegistration,
  deleteCustomerPasskeyCredential,
  finishCustomerPasskeyAssertion,
  finishCustomerPasskeyRegistration,
  listCustomerPasskeyCredentials,
} from "./passkeyAuthHandlers";
export { verifyQRCode } from "./verificationHandlers";
export {
  getCustomerVerificationSessionState,
  revealCustomerVerificationResult,
  startCustomerVerificationSession,
  submitCustomerVerificationIntake,
} from "./sessionHandlers";
export { claimProductOwnership, linkDeviceClaimToCustomer } from "./claimHandlers";
export {
  acceptOwnershipTransfer,
  cancelOwnershipTransfer,
  createOwnershipTransfer,
} from "./transferHandlers";
export { reportFraud, submitProductFeedback } from "./feedbackHandlers";
