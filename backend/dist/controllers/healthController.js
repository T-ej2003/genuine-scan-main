"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.healthCheck = void 0;
const database_1 = __importDefault(require("../config/database"));
const healthCheck = async (_req, res) => {
    const started = Date.now();
    try {
        await database_1.default.$queryRaw `SELECT 1`;
        return res.json({
            success: true,
            status: "ok",
            db: "ok",
            uptimeSec: Math.round(process.uptime()),
            timestamp: new Date().toISOString(),
            ms: Date.now() - started,
        });
    }
    catch (e) {
        return res.json({
            success: true,
            status: "degraded",
            db: "error",
            error: e?.message || "db error",
            uptimeSec: Math.round(process.uptime()),
            timestamp: new Date().toISOString(),
            ms: Date.now() - started,
        });
    }
};
exports.healthCheck = healthCheck;
//# sourceMappingURL=healthController.js.map