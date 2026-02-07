"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateScanPolicy = void 0;
const client_1 = require("@prisma/client");
const evaluateScanPolicy = (status) => {
    switch (status) {
        case client_1.QRStatus.PRINTED:
            return { outcome: "VALID", isFirstScan: true, allowRedeem: true };
        case client_1.QRStatus.REDEEMED:
        case client_1.QRStatus.SCANNED:
            return { outcome: "ALREADY_REDEEMED", isFirstScan: false, allowRedeem: false };
        case client_1.QRStatus.ACTIVATED:
            return { outcome: "SUSPICIOUS", isFirstScan: false, allowRedeem: false };
        case client_1.QRStatus.BLOCKED:
            return { outcome: "BLOCKED", isFirstScan: false, allowRedeem: false };
        case client_1.QRStatus.DORMANT:
        case client_1.QRStatus.ACTIVE:
        case client_1.QRStatus.ALLOCATED:
        default:
            return { outcome: "NOT_PRINTED", isFirstScan: false, allowRedeem: false };
    }
};
exports.evaluateScanPolicy = evaluateScanPolicy;
//# sourceMappingURL=scanPolicy.js.map