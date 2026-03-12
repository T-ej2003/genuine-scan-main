"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDashboardStats = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const manufacturerScopeService_1 = require("../services/manufacturerScopeService");
const getDashboardStats = async (req, res) => {
    try {
        const role = req.user?.role;
        const userId = req.user?.userId;
        const licenseeId = req.user?.licenseeId || null;
        if (!role || !userId) {
            return res.status(401).json({ success: false, error: "Not authenticated" });
        }
        // SUPER_ADMIN can optionally scope by ?licenseeId=
        const scopeLicenseeId = role === client_1.UserRole.SUPER_ADMIN || role === client_1.UserRole.PLATFORM_SUPER_ADMIN
            ? (req.query.licenseeId || null)
            : licenseeId;
        const qrWhere = {};
        const batchWhere = {};
        // Manufacturers count:
        // - SUPER_ADMIN (no scope): all manufacturers
        // - SUPER_ADMIN (scoped): manufacturers inside that licensee
        // - LICENSEE_ADMIN: manufacturers in own licensee
        // - MANUFACTURER: only self (personal scope)
        const mfgWhere = {
            role: { in: [client_1.UserRole.MANUFACTURER, client_1.UserRole.MANUFACTURER_ADMIN, client_1.UserRole.MANUFACTURER_USER] },
            isActive: true,
        };
        if (role === client_1.UserRole.MANUFACTURER ||
            role === client_1.UserRole.MANUFACTURER_ADMIN ||
            role === client_1.UserRole.MANUFACTURER_USER) {
            batchWhere.manufacturerId = userId;
            qrWhere.batch = { manufacturerId: userId };
            mfgWhere.id = userId;
        }
        else if (scopeLicenseeId) {
            qrWhere.licenseeId = scopeLicenseeId;
            batchWhere.licenseeId = scopeLicenseeId;
            mfgWhere.OR = [{ licenseeId: scopeLicenseeId }, { manufacturerLicenseeLinks: { some: { licenseeId: scopeLicenseeId } } }];
        }
        const linkedLicenseeIds = role === client_1.UserRole.MANUFACTURER || role === client_1.UserRole.MANUFACTURER_ADMIN || role === client_1.UserRole.MANUFACTURER_USER
            ? await (0, manufacturerScopeService_1.resolveAccessibleLicenseeIdsForUser)(req.user)
            : [];
        const [totalQRCodes, activeLicensees, manufacturers, totalBatches,] = await Promise.all([
            database_1.default.qRCode.count({ where: qrWhere }),
            role === client_1.UserRole.SUPER_ADMIN || role === client_1.UserRole.PLATFORM_SUPER_ADMIN
                ? database_1.default.licensee.count({ where: { ...(scopeLicenseeId ? { id: scopeLicenseeId } : {}), isActive: true } })
                : linkedLicenseeIds.length > 0
                    ? database_1.default.licensee.count({ where: { id: { in: linkedLicenseeIds }, isActive: true } })
                    : scopeLicenseeId
                        ? database_1.default.licensee.count({ where: { id: scopeLicenseeId, isActive: true } })
                        : 0,
            database_1.default.user.count({ where: mfgWhere }),
            database_1.default.batch.count({ where: batchWhere }),
        ]);
        return res.json({
            success: true,
            data: { totalQRCodes, activeLicensees, manufacturers, totalBatches },
        });
    }
    catch (err) {
        console.error("getDashboardStats error", err);
        return res.status(500).json({ success: false, error: "Failed to load dashboard stats" });
    }
};
exports.getDashboardStats = getDashboardStats;
//# sourceMappingURL=dashboardController.js.map