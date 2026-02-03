"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.me = exports.login = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email("Invalid email format"),
    password: zod_1.z.string().min(6, "Password must be at least 6 characters"),
});
const login = async (req, res) => {
    try {
        const validation = loginSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({
                success: false,
                error: validation.error.errors[0]?.message ?? "Invalid request",
            });
        }
        const { email, password } = validation.data;
        const user = await database_1.default.user.findUnique({
            where: { email: email.toLowerCase() },
            include: { licensee: true },
        });
        if (!user) {
            return res.status(401).json({ success: false, error: "Invalid email or password" });
        }
        const isValidPassword = await bcryptjs_1.default.compare(password, user.passwordHash);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, error: "Invalid email or password" });
        }
        if (user.deletedAt || user.isActive === false) {
            return res.status(403).json({
                success: false,
                error: "Account is deactivated. Contact administrator.",
            });
        }
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
            return res.status(500).json({ success: false, error: "JWT secret not configured" });
        }
        const expiresIn = process.env.JWT_EXPIRES_IN || "7d";
        const signOptions = { expiresIn: expiresIn };
        const token = jsonwebtoken_1.default.sign({
            userId: user.id,
            email: user.email,
            role: user.role,
            licenseeId: user.licenseeId,
        }, jwtSecret, signOptions);
        await (0, auditService_1.createAuditLog)({
            userId: user.id,
            licenseeId: user.licenseeId ?? undefined,
            action: "LOGIN",
            entityType: "User",
            entityId: user.id,
            ipAddress: req.ip,
        });
        return res.json({
            success: true,
            data: {
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    licenseeId: user.licenseeId,
                    licensee: user.licensee
                        ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix }
                        : null,
                },
            },
        });
    }
    catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.login = login;
const me = async (req, res) => {
    try {
        const authReq = req;
        const userId = authReq.user?.userId;
        if (!userId) {
            return res.status(401).json({ success: false, error: "Not authenticated" });
        }
        const user = await database_1.default.user.findUnique({
            where: { id: userId },
            include: { licensee: true },
        });
        if (!user) {
            return res.status(404).json({ success: false, error: "User not found" });
        }
        return res.json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                licenseeId: user.licenseeId,
                licensee: user.licensee
                    ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix }
                    : null,
            },
        });
    }
    catch (error) {
        console.error("Me error:", error);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.me = me;
//# sourceMappingURL=authController.js.map