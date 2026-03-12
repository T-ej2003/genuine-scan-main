"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compactDeviceLabel = exports.locationLabelFromCoords = exports.reverseGeocode = void 0;
const LOCATION_CACHE_TTL_MS = 6 * 60 * 60_000;
const GEO_TIMEOUT_MS = Number(process.env.GEO_REVERSE_TIMEOUT_MS || "1200");
const GEO_ENABLED = String(process.env.GEO_REVERSE_ENABLED || "true").toLowerCase() !== "false";
const GEO_PROVIDER = String(process.env.GEO_REVERSE_PROVIDER || "nominatim").toLowerCase();
const locationCache = new Map();
const normalizeCoord = (value) => Number(value.toFixed(3));
const cacheKey = (lat, lon) => `${normalizeCoord(lat)}:${normalizeCoord(lon)}`;
const withTimeout = async (p, timeoutMs) => {
    let timer = null;
    try {
        return await Promise.race([
            p,
            new Promise((_resolve, reject) => {
                timer = setTimeout(() => reject(new Error("reverse-geocode-timeout")), timeoutMs);
            }),
        ]);
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
};
const readFromCache = (key) => {
    const hit = locationCache.get(key);
    if (!hit)
        return null;
    if (hit.expiresAt < Date.now()) {
        locationCache.delete(key);
        return null;
    }
    return hit.value;
};
const writeCache = (key, value) => {
    locationCache.set(key, { value, expiresAt: Date.now() + LOCATION_CACHE_TTL_MS });
};
const getNominatimLocation = async (lat, lon) => {
    const url = `https://nominatim.openstreetmap.org/reverse` +
        `?format=jsonv2&lat=${encodeURIComponent(String(lat))}` +
        `&lon=${encodeURIComponent(String(lon))}` +
        `&zoom=13&addressdetails=1`;
    const appName = String(process.env.APP_NAME || "MSCQR");
    const resp = await withTimeout(fetch(url, {
        headers: {
            "User-Agent": `${appName}/1.0`,
            "Accept": "application/json",
        },
    }), GEO_TIMEOUT_MS);
    if (!resp.ok)
        return null;
    const payload = await resp.json().catch(() => null);
    if (!payload || typeof payload !== "object")
        return null;
    const address = payload.address && typeof payload.address === "object" ? payload.address : {};
    const country = String(address.country || "").trim() || null;
    const region = String(address.state ||
        address.region ||
        address.county ||
        address.province ||
        "").trim() || null;
    const city = String(address.city ||
        address.town ||
        address.village ||
        address.municipality ||
        address.suburb ||
        "").trim() || null;
    const nameParts = [city, region, country].filter(Boolean);
    const name = nameParts.length > 0 ? nameParts.join(", ") : null;
    return { name, country, region, city };
};
const reverseGeocode = async (lat, lon) => {
    if (!GEO_ENABLED)
        return null;
    if (lat == null || lon == null)
        return null;
    if (!Number.isFinite(lat) || !Number.isFinite(lon))
        return null;
    if (GEO_PROVIDER !== "nominatim")
        return null;
    const key = cacheKey(lat, lon);
    const cached = readFromCache(key);
    if (cached)
        return cached;
    try {
        const resolved = await getNominatimLocation(lat, lon);
        if (!resolved)
            return null;
        writeCache(key, resolved);
        return resolved;
    }
    catch {
        return null;
    }
};
exports.reverseGeocode = reverseGeocode;
const locationLabelFromCoords = async (lat, lon) => {
    const geo = await (0, exports.reverseGeocode)(lat, lon);
    return geo?.name || null;
};
exports.locationLabelFromCoords = locationLabelFromCoords;
const compactDeviceLabel = (raw) => {
    const value = String(raw || "").trim();
    if (!value)
        return null;
    const browser = /Edg\//i.test(value)
        ? "Edge"
        : /Chrome\//i.test(value)
            ? "Chrome"
            : /Firefox\//i.test(value)
                ? "Firefox"
                : /Safari\//i.test(value)
                    ? "Safari"
                    : "Browser";
    const os = /Windows/i.test(value)
        ? "Windows"
        : /Android/i.test(value)
            ? "Android"
            : /iPhone|iPad|iOS/i.test(value)
                ? "iOS"
                : /Mac OS X|Macintosh/i.test(value)
                    ? "macOS"
                    : /Linux/i.test(value)
                        ? "Linux"
                        : null;
    return os ? `${browser} on ${os}` : browser;
};
exports.compactDeviceLabel = compactDeviceLabel;
//# sourceMappingURL=locationService.js.map