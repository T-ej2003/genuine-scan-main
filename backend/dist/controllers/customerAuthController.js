"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logoutCustomer = exports.verifyCustomerOtp = exports.requestCustomerOtp = exports.googleCustomerAuth = exports.getCurrentCustomer = void 0;
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const customerSessionService_1 = require("../services/customerSessionService");
const customerAuthService_1 = require("../services/customerAuthService");
const googleAuthSchema = zod_1.z.object({
    idToken: zod_1.z.string().trim().min(20),
});
const otpRequestSchema = zod_1.z.object({
    email: zod_1.z.string().trim().email().max(160),
    name: zod_1.z.string().trim().max(120).optional(),
});
const otpVerifySchema = zod_1.z.object({
    email: zod_1.z.string().trim().email().max(160),
    otp: zod_1.z.string().trim().min(4).max(10),
    name: zod_1.z.string().trim().max(120).optional(),
});
const asCustomerPayload = (user) => ({
    id: user.id,
    email: user.email,
    name: user.name,
    provider: user.provider,
    createdAt: user.createdAt,
});
const getCurrentCustomer = async (req, res) => {
    try {
        const identity = (0, customerSessionService_1.getCustomerIdentityContext)(req, res);
        if (!identity.customerUserId) {
            return res.json({
                success: true,
                data: {
                    user: null,
                    anonVisitorId: identity.anonVisitorId,
                },
            });
        }
        const user = await database_1.default.customerUser.findUnique({
            where: { id: identity.customerUserId },
            select: {
                id: true,
                email: true,
                name: true,
                provider: true,
                createdAt: true,
            },
        });
        if (!user) {
            (0, customerSessionService_1.clearCustomerSession)(res);
            return res.json({
                success: true,
                data: {
                    user: null,
                    anonVisitorId: identity.anonVisitorId,
                },
            });
        }
        return res.json({
            success: true,
            data: {
                user: asCustomerPayload(user),
                anonVisitorId: identity.anonVisitorId,
            },
        });
    }
    catch (error) {
        console.error("getCurrentCustomer error:", error);
        return res.status(500).json({ success: false, error: "Failed to load current customer" });
    }
};
exports.getCurrentCustomer = getCurrentCustomer;
const googleCustomerAuth = async (req, res) => {
    try {
        const parsed = googleAuthSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
        }
        const user = await (0, customerAuthService_1.authenticateWithGoogle)({ idToken: parsed.data.idToken });
        (0, customerSessionService_1.issueCustomerSession)(res, {
            id: user.id,
            email: user.email,
            name: user.name,
            provider: user.provider,
        });
        const identity = (0, customerSessionService_1.getCustomerIdentityContext)(req, res);
        return res.json({
            success: true,
            data: {
                user: asCustomerPayload(user),
                anonVisitorId: identity.anonVisitorId,
            },
        });
    }
    catch (error) {
        const msg = error?.message || "Google sign-in failed";
        return res.status(400).json({ success: false, error: msg });
    }
};
exports.googleCustomerAuth = googleCustomerAuth;
const requestCustomerOtp = async (req, res) => {
    try {
        const parsed = otpRequestSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
        }
        const out = await (0, customerAuthService_1.requestEmailOtp)({
            email: parsed.data.email,
            name: parsed.data.name,
        });
        return res.json({
            success: true,
            data: {
                delivered: out.delivered,
                expiresAt: out.expiresAt,
            },
        });
    }
    catch (error) {
        return res.status(400).json({ success: false, error: error?.message || "Could not send OTP" });
    }
};
exports.requestCustomerOtp = requestCustomerOtp;
const verifyCustomerOtp = async (req, res) => {
    try {
        const parsed = otpVerifySchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
        }
        const user = await (0, customerAuthService_1.verifyEmailOtp)({
            email: parsed.data.email,
            otp: parsed.data.otp,
            name: parsed.data.name,
        });
        (0, customerSessionService_1.issueCustomerSession)(res, {
            id: user.id,
            email: user.email,
            name: user.name,
            provider: user.provider,
        });
        const identity = (0, customerSessionService_1.getCustomerIdentityContext)(req, res);
        return res.json({
            success: true,
            data: {
                user: asCustomerPayload(user),
                anonVisitorId: identity.anonVisitorId,
            },
        });
    }
    catch (error) {
        return res.status(400).json({ success: false, error: error?.message || "OTP verification failed" });
    }
};
exports.verifyCustomerOtp = verifyCustomerOtp;
const logoutCustomer = async (_req, res) => {
    (0, customerSessionService_1.clearCustomerSession)(res);
    return res.json({ success: true, data: { loggedOut: true } });
};
exports.logoutCustomer = logoutCustomer;
//# sourceMappingURL=customerAuthController.js.map