export { requestCustomerEmailOtp, verifyCustomerEmailOtp } from "./authHandlers";
export { verifyQRCode } from "./verificationHandlers";
export { claimProductOwnership, linkDeviceClaimToCustomer } from "./claimHandlers";
export {
  acceptOwnershipTransfer,
  cancelOwnershipTransfer,
  createOwnershipTransfer,
} from "./transferHandlers";
export { reportFraud, submitProductFeedback } from "./feedbackHandlers";
