"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.classifyScan = void 0;
const client_1 = require("@prisma/client");
const toMs = (input) => {
    if (!input)
        return NaN;
    const dt = input instanceof Date ? input : new Date(input);
    return dt.getTime();
};
const safeLower = (value) => String(value || "").trim().toLowerCase();
const toRad = (deg) => (deg * Math.PI) / 180;
const haversineKm = (aLat, aLon, bLat, bLon) => {
    const R = 6371;
    const dLat = toRad(bLat - aLat);
    const dLon = toRad(bLon - aLon);
    const lat1 = toRad(aLat);
    const lat2 = toRad(bLat);
    const h = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
};
const distanceKm = (a, b) => {
    if (a.latitude == null ||
        a.longitude == null ||
        b.latitude == null ||
        b.longitude == null ||
        !Number.isFinite(a.latitude) ||
        !Number.isFinite(a.longitude) ||
        !Number.isFinite(b.latitude) ||
        !Number.isFinite(b.longitude)) {
        return null;
    }
    return haversineKm(a.latitude, a.longitude, b.latitude, b.longitude);
};
const isLocationConsistent = (current, latest) => {
    if (!latest)
        return true;
    const dist = distanceKm(current, latest);
    if (dist != null)
        return dist <= 250;
    const cCountry = safeLower(current.locationCountry);
    const lCountry = safeLower(latest.locationCountry);
    if (!cCountry || !lCountry)
        return true;
    return cCountry === lCountry;
};
const detectImpossibleTravel = (current, history) => {
    const currentTs = toMs(current.scannedAt);
    if (!Number.isFinite(currentTs))
        return false;
    for (const entry of history) {
        const entryTs = toMs(entry.scannedAt);
        if (!Number.isFinite(entryTs))
            continue;
        const deltaHours = Math.abs(currentTs - entryTs) / 3_600_000;
        if (deltaHours <= 0 || deltaHours > 6)
            continue;
        const dist = distanceKm(current, entry);
        if (dist != null) {
            const speed = dist / deltaHours;
            if (speed > 900)
                return true;
            continue;
        }
        const currCountry = safeLower(current.locationCountry);
        const prevCountry = safeLower(entry.locationCountry);
        if (currCountry && prevCountry && currCountry !== prevCountry && deltaHours <= 2) {
            return true;
        }
    }
    return false;
};
const detectBurstyPattern = (current, history) => {
    const currentTs = toMs(current.scannedAt);
    if (!Number.isFinite(currentTs))
        return false;
    const recentCount = history.filter((entry) => {
        const ts = toMs(entry.scannedAt);
        if (!Number.isFinite(ts))
            return false;
        return currentTs - ts >= 0 && currentTs - ts <= 10 * 60_000;
    }).length;
    return recentCount >= 4;
};
const classifyScan = (context, scanHistory) => {
    const history = [...scanHistory].sort((a, b) => toMs(b.scannedAt) - toMs(a.scannedAt));
    if (history.length === 0) {
        return {
            classification: client_1.ScanRiskClassification.FIRST_SCAN,
            reasons: ["First recorded verification"],
            metrics: {
                totalPriorScans: 0,
                distinctCustomerCount: 0,
                distinctVisitorCount: 0,
                verifiedByYouCount: 0,
            },
        };
    }
    const currentUserId = String(context.customerUserId || "").trim() || null;
    const currentAnonId = String(context.anonVisitorId || "").trim() || null;
    const ownerUserId = String(context.ownerCustomerUserId || "").trim() || null;
    const distinctCustomerIds = new Set(history
        .map((s) => String(s.customerUserId || "").trim())
        .filter(Boolean));
    const distinctVisitorIds = new Set(history
        .map((s) => String(s.anonVisitorId || "").trim())
        .filter(Boolean));
    if (currentUserId)
        distinctCustomerIds.add(currentUserId);
    if (currentAnonId)
        distinctVisitorIds.add(currentAnonId);
    const verifiedByYouCount = history.filter((entry) => {
        if (currentUserId && entry.customerUserId === currentUserId)
            return true;
        if (!currentUserId && currentAnonId && entry.anonVisitorId === currentAnonId)
            return true;
        return false;
    }).length;
    const latest = history[0] || null;
    const ownerMatch = Boolean(currentUserId && ownerUserId && currentUserId === ownerUserId);
    const ownerConflict = Boolean(currentUserId && ownerUserId && currentUserId !== ownerUserId);
    const seenUserBefore = Boolean(currentUserId && history.some((entry) => entry.customerUserId === currentUserId));
    const seenAnonBefore = Boolean(currentAnonId && history.some((entry) => entry.anonVisitorId === currentAnonId));
    const locationConsistent = isLocationConsistent(context, latest);
    const reasons = [];
    if (ownerMatch)
        reasons.push("Matched claimed owner account");
    if (seenUserBefore && !ownerMatch)
        reasons.push("Matched previous account activity");
    if (seenAnonBefore && locationConsistent)
        reasons.push("Matched previous device pattern");
    const hasDifferentAccount = Boolean(currentUserId && history.some((entry) => entry.customerUserId && entry.customerUserId !== currentUserId));
    if (ownerConflict)
        reasons.push("Different account than claimed owner");
    if (hasDifferentAccount)
        reasons.push("Different account seen on this code");
    if (distinctCustomerIds.size > 1)
        reasons.push("Multiple customer accounts detected");
    if (distinctVisitorIds.size > 2)
        reasons.push("Multiple devices detected");
    if (!locationConsistent && seenAnonBefore)
        reasons.push("Device location changed unusually");
    const impossibleTravel = detectImpossibleTravel(context, history);
    if (impossibleTravel)
        reasons.push("Impossible travel pattern");
    const bursty = detectBurstyPattern(context, history);
    if (bursty)
        reasons.push("High scan frequency in a short time");
    const legitRepeat = ownerMatch || seenUserBefore || (seenAnonBefore && locationConsistent);
    const hardSuspicious = ownerConflict ||
        hasDifferentAccount ||
        distinctCustomerIds.size > 1 ||
        distinctVisitorIds.size > 2 ||
        impossibleTravel ||
        bursty;
    const fallbackSuspicious = !legitRepeat && history.length >= 1;
    if (legitRepeat && !hardSuspicious) {
        return {
            classification: client_1.ScanRiskClassification.LEGIT_REPEAT,
            reasons: reasons.length > 0 ? reasons : ["Repeat verification matched prior identity"],
            metrics: {
                totalPriorScans: history.length,
                distinctCustomerCount: distinctCustomerIds.size,
                distinctVisitorCount: distinctVisitorIds.size,
                verifiedByYouCount,
            },
        };
    }
    if (hardSuspicious || fallbackSuspicious) {
        return {
            classification: client_1.ScanRiskClassification.SUSPICIOUS_DUPLICATE,
            reasons: reasons.length > 0 ? reasons : ["Different identity from prior verification"],
            metrics: {
                totalPriorScans: history.length,
                distinctCustomerCount: distinctCustomerIds.size,
                distinctVisitorCount: distinctVisitorIds.size,
                verifiedByYouCount,
            },
        };
    }
    return {
        classification: client_1.ScanRiskClassification.LEGIT_REPEAT,
        reasons: reasons.length > 0 ? reasons : ["Repeat verification"],
        metrics: {
            totalPriorScans: history.length,
            distinctCustomerCount: distinctCustomerIds.size,
            distinctVisitorCount: distinctVisitorIds.size,
            verifiedByYouCount,
        },
    };
};
exports.classifyScan = classifyScan;
//# sourceMappingURL=scanRiskService.js.map