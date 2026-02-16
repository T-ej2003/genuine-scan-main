"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.streamAuditLogs = void 0;
const auditStream_1 = require("../events/auditStream");
const client_1 = require("@prisma/client");
// SSE uses EventSource on browser which cannot send Authorization header.
// We'll accept token via query (?token=...) safely for localhost.
// If you want stricter security later, we can switch to cookie-based auth.
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function authenticateSSE(req) {
    const token = req.query.token || "";
    if (!token)
        return null;
    try {
        return jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
    }
    catch {
        return null;
    }
}
const streamAuditLogs = async (req, res) => {
    const user = authenticateSSE(req);
    if (!user)
        return res.status(401).json({ success: false, error: "Unauthorized SSE" });
    // Visibility rule:
    // - SUPER_ADMIN: sees all
    // - LICENSEE_ADMIN: sees only their licensee (requires licenseeId stored on logs)
    // - MANUFACTURER: usually no access (you said controls yes all, but normally no)
    if (user.role !== client_1.UserRole.SUPER_ADMIN &&
        user.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN &&
        user.role !== client_1.UserRole.LICENSEE_ADMIN &&
        user.role !== client_1.UserRole.ORG_ADMIN) {
        return res.status(403).json({ success: false, error: "Access denied" });
    }
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();
    const heartbeat = setInterval(() => {
        res.write(`event: ping\ndata: {}\n\n`);
    }, 25000);
    const off = auditStream_1.auditStream.onLog((evt) => {
        // tenant filter (only works well if AuditLog has licenseeId)
        if (user.role === client_1.UserRole.LICENSEE_ADMIN || user.role === client_1.UserRole.ORG_ADMIN) {
            if (!user.licenseeId)
                return;
            if ((evt.licenseeId || null) !== user.licenseeId)
                return;
        }
        res.write(`event: audit\ndata: ${JSON.stringify(evt)}\n\n`);
    });
    req.on("close", () => {
        clearInterval(heartbeat);
        off();
        res.end();
    });
};
exports.streamAuditLogs = streamAuditLogs;
//# sourceMappingURL=auditStreamController.js.map