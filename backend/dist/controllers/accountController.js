"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.changeMyPassword = exports.updateMyProfile = void 0;
const zod_1 = require("zod");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const updateProfileSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(2).max(80).optional(),
    email: zod_1.z.string().trim().email().optional(),
});
const changePasswordSchema = zod_1.z.object({
    currentPassword: zod_1.z.string().min(1),
    newPassword: zod_1.z.string().min(6).max(200),
});
const updateMyProfile = async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = updateProfileSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const data = {};
        if (parsed.data.name !== undefined)
            data.name = parsed.data.name;
        if (parsed.data.email !== undefined)
            data.email = parsed.data.email.toLowerCase();
        if (!Object.keys(data).length) {
            return res.status(400).json({ success: false, error: "No changes provided" });
        }
        // email uniqueness check (if changing email)
        if (data.email) {
            const exists = await database_1.default.user.findUnique({ where: { email: data.email } });
            if (exists && exists.id !== userId) {
                return res.status(409).json({ success: false, error: "Email already in use" });
            }
        }
        const updated = await database_1.default.user.update({
            where: { id: userId },
            data,
            select: { id: true, name: true, email: true, role: true, licenseeId: true, isActive: true, createdAt: true },
        });
        await (0, auditService_1.createAuditLog)({
            userId,
            action: "UPDATE_MY_PROFILE",
            entityType: "User",
            entityId: userId,
            details: { changed: Object.keys(data) },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("updateMyProfile error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.updateMyProfile = updateMyProfile;
const changeMyPassword = async (req, res) => {
    try {
        const userId = req.user?.userId;
        if (!userId)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = changePasswordSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const user = await database_1.default.user.findUnique({
            where: { id: userId },
            select: { id: true, passwordHash: true },
        });
        if (!user)
            return res.status(404).json({ success: false, error: "User not found" });
        const ok = await bcryptjs_1.default.compare(parsed.data.currentPassword, user.passwordHash);
        if (!ok) {
            return res.status(400).json({ success: false, error: "Current password is incorrect" });
        }
        const passwordHash = await bcryptjs_1.default.hash(parsed.data.newPassword, 10);
        await database_1.default.user.update({
            where: { id: userId },
            data: { passwordHash },
        });
        await (0, auditService_1.createAuditLog)({
            userId,
            action: "CHANGE_MY_PASSWORD",
            entityType: "User",
            entityId: userId,
            details: {},
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: { changed: true } });
    }
    catch (e) {
        console.error("changeMyPassword error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.changeMyPassword = changeMyPassword;
//# sourceMappingURL=accountController.js.map