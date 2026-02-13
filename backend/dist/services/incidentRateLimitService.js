"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.enforceIncidentRateLimit = void 0;
const DEFAULT_WINDOW_MS = Number(process.env.INCIDENT_RATE_LIMIT_WINDOW_MS || "3600000");
const DEFAULT_MAX_PER_KEY = Number(process.env.INCIDENT_RATE_LIMIT_MAX_PER_KEY || "8");
const buckets = new Map();
const upsertBucket = (key, now) => {
    const existing = buckets.get(key);
    if (!existing || existing.resetAt <= now) {
        const fresh = { count: 0, resetAt: now + DEFAULT_WINDOW_MS };
        buckets.set(key, fresh);
        return fresh;
    }
    return existing;
};
const hitKey = (key) => {
    const now = Date.now();
    const bucket = upsertBucket(key, now);
    bucket.count += 1;
    const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    return {
        blocked: bucket.count > DEFAULT_MAX_PER_KEY,
        retryAfterSec,
    };
};
const makeKey = (prefix, value) => {
    const normalized = String(value || "").trim().toLowerCase();
    if (!normalized)
        return null;
    return `${prefix}:${normalized}`;
};
const enforceIncidentRateLimit = (input) => {
    const keys = [
        makeKey("ip", input.ip),
        makeKey("qr", input.qrCode),
        makeKey("dev", input.deviceFp),
        makeKey("mix", `${input.ip || ""}|${input.qrCode || ""}|${input.deviceFp || ""}`),
    ].filter(Boolean);
    if (keys.length === 0) {
        return { blocked: false, retryAfterSec: 0 };
    }
    let maxRetry = 0;
    for (const key of keys) {
        const result = hitKey(key);
        if (result.retryAfterSec > maxRetry)
            maxRetry = result.retryAfterSec;
        if (result.blocked) {
            return { blocked: true, retryAfterSec: result.retryAfterSec };
        }
    }
    return { blocked: false, retryAfterSec: maxRetry };
};
exports.enforceIncidentRateLimit = enforceIncidentRateLimit;
//# sourceMappingURL=incidentRateLimitService.js.map