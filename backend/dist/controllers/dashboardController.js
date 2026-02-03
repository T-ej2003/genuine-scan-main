"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getDashboardStats = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const getDashboardStats = async (req, res) => {
    try {
        const role = req.user?.role;
        const userId = req.user?.userId;
        const licenseeId = req.user?.licenseeId || null;
        if (!role || !userId) {
            return res.status(401).json({ success: false, error: "Not authenticated" });
        }
        // SUPER_ADMIN can optionally scope by ?licenseeId=
        const scopeLicenseeId = role === client_1.UserRole.SUPER_ADMIN ? (req.query.licenseeId || null) : licenseeId;
        const qrWhere = scopeLicenseeId ? { licenseeId: scopeLicenseeId } : {};
        const licenseeWhere = scopeLicenseeId ? { id: scopeLicenseeId } : {};
        // Manufacturers count:
        // - SUPER_ADMIN (no scope): all manufacturers
        // - SUPER_ADMIN (scoped): manufacturers inside that licensee
        // - LICENSEE_ADMIN: manufacturers in own licensee
        // - MANUFACTURER: manufacturers in own licensee (so dashboard is consistent)
        const mfgWhere = { role: client_1.UserRole.MANUFACTURER, isActive: true };
        if (scopeLicenseeId)
            mfgWhere.licenseeId = scopeLicenseeId;
        // Batches:
        const batchWhere = {};
        if (scopeLicenseeId)
            batchWhere.licenseeId = scopeLicenseeId;
        if (role === client_1.UserRole.MANUFACTURER)
            batchWhere.manufacturerId = userId;
        const productBatchWhere = {};
        if (scopeLicenseeId)
            productBatchWhere.licenseeId = scopeLicenseeId;
        if (role === client_1.UserRole.MANUFACTURER)
            productBatchWhere.manufacturerId = userId;
        const [totalQRCodes, activeLicensees, manufacturers, totalBatches, totalProductBatches,] = await Promise.all([
            database_1.default.qRCode.count({ where: qrWhere }),
            database_1.default.licensee.count({ where: { ...licenseeWhere, isActive: true } }),
            database_1.default.user.count({ where: mfgWhere }),
            database_1.default.batch.count({ where: batchWhere }),
            database_1.default.productBatch.count({ where: productBatchWhere }),
        ]);
        return res.json({
            success: true,
            data: { totalQRCodes, activeLicensees, manufacturers, totalBatches, totalProductBatches },
        });
    }
    catch (err) {
        console.error("getDashboardStats error", err);
        return res.status(500).json({ success: false, error: "Failed to load dashboard stats" });
    }
};
exports.getDashboardStats = getDashboardStats;
//# sourceMappingURL=dashboardController.js.map