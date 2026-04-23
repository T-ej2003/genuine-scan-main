import type { CustomerVerifyIdentity } from "../../services/customerVerifyAuthService";
import { maskEmail } from "../../services/customerVerifyAuthService";

export const buildCustomerVerifyIdentityResponse = (customer: CustomerVerifyIdentity) => ({
  userId: customer.userId,
  email: customer.email,
  maskedEmail: maskEmail(customer.email),
  displayName: customer.displayName || null,
  authProvider: customer.authProvider === "GOOGLE" ? "GOOGLE" : undefined,
});

export const buildCustomerVerifyAuthResponse = (customer: CustomerVerifyIdentity) => ({
  customer: buildCustomerVerifyIdentityResponse(customer),
  auth: {
    cookieBacked: true,
    authenticated: true,
    authStrength: customer.authStrength || "EMAIL_OTP",
    webauthnVerifiedAt: customer.webauthnVerifiedAt || null,
    authProvider: customer.authProvider || "EMAIL_OTP",
  },
});

export const buildAnonymousCustomerVerifyAuthResponse = () => ({
  customer: null,
  auth: {
    cookieBacked: true,
    authenticated: false,
    authStrength: null,
    webauthnVerifiedAt: null,
    authProvider: null,
  },
});
