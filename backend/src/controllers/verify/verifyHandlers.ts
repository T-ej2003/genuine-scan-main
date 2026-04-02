export { requestCustomerEmailOtp, verifyCustomerEmailOtp } from "./authHandlers";
export {
  beginCustomerPasskeyAssertion,
  beginCustomerPasskeyRegistration,
  deleteCustomerPasskeyCredential,
  finishCustomerPasskeyAssertion,
  finishCustomerPasskeyRegistration,
  listCustomerPasskeyCredentials,
} from "./passkeyAuthHandlers";
export { verifyQRCode } from "./verificationHandlers";
export { claimProductOwnership, linkDeviceClaimToCustomer } from "./claimHandlers";
export {
  acceptOwnershipTransfer,
  cancelOwnershipTransfer,
  createOwnershipTransfer,
} from "./transferHandlers";
export { reportFraud, submitProductFeedback } from "./feedbackHandlers";
