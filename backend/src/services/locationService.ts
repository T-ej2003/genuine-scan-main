type LocationLookupResult = {
  name: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
};

type CacheEntry = {
  value: LocationLookupResult;
  expiresAt: number;
};

const LOCATION_CACHE_TTL_MS = 6 * 60 * 60_000;
const GEO_TIMEOUT_MS = Number(process.env.GEO_REVERSE_TIMEOUT_MS || "1200");
const GEO_ENABLED = String(process.env.GEO_REVERSE_ENABLED || "true").toLowerCase() !== "false";
const GEO_PROVIDER = String(process.env.GEO_REVERSE_PROVIDER || "nominatim").toLowerCase();

const locationCache = new Map<string, CacheEntry>();

const normalizeCoord = (value: number) => Number(value.toFixed(3));

const cacheKey = (lat: number, lon: number) => `${normalizeCoord(lat)}:${normalizeCoord(lon)}`;

const withTimeout = async <T>(p: Promise<T>, timeoutMs: number): Promise<T> => {
  let timer: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      p,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("reverse-geocode-timeout")), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const readFromCache = (key: string): LocationLookupResult | null => {
  const hit = locationCache.get(key);
  if (!hit) return null;
  if (hit.expiresAt < Date.now()) {
    locationCache.delete(key);
    return null;
  }
  return hit.value;
};

const writeCache = (key: string, value: LocationLookupResult) => {
  locationCache.set(key, { value, expiresAt: Date.now() + LOCATION_CACHE_TTL_MS });
};

const getNominatimLocation = async (lat: number, lon: number): Promise<LocationLookupResult | null> => {
  const url =
    `https://nominatim.openstreetmap.org/reverse` +
    `?format=jsonv2&lat=${encodeURIComponent(String(lat))}` +
    `&lon=${encodeURIComponent(String(lon))}` +
    `&zoom=13&addressdetails=1`;

  const appName = String(process.env.APP_NAME || "MSCQR");
  const resp = await withTimeout(
    fetch(url, {
      headers: {
        "User-Agent": `${appName}/1.0`,
        "Accept": "application/json",
      },
    }),
    GEO_TIMEOUT_MS
  );

  if (!resp.ok) return null;

  const payload: any = await resp.json().catch(() => null);
  if (!payload || typeof payload !== "object") return null;

  const address = payload.address && typeof payload.address === "object" ? payload.address : {};

  const country = String(address.country || "").trim() || null;
  const region =
    String(
      address.state ||
        address.region ||
        address.county ||
        address.province ||
        ""
    ).trim() || null;
  const city =
    String(
      address.city ||
        address.town ||
        address.village ||
        address.municipality ||
        address.suburb ||
        ""
    ).trim() || null;

  const nameParts = [city, region, country].filter(Boolean);
  const name = nameParts.length > 0 ? nameParts.join(", ") : null;

  return { name, country, region, city };
};

export const reverseGeocode = async (lat?: number | null, lon?: number | null): Promise<LocationLookupResult | null> => {
  if (!GEO_ENABLED) return null;
  if (lat == null || lon == null) return null;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (GEO_PROVIDER !== "nominatim") return null;

  const key = cacheKey(lat, lon);
  const cached = readFromCache(key);
  if (cached) return cached;

  try {
    const resolved = await getNominatimLocation(lat, lon);
    if (!resolved) return null;
    writeCache(key, resolved);
    return resolved;
  } catch {
    return null;
  }
};

export const locationLabelFromCoords = async (lat?: number | null, lon?: number | null): Promise<string | null> => {
  const geo = await reverseGeocode(lat, lon);
  return geo?.name || null;
};

export const compactDeviceLabel = (raw?: string | null): string | null => {
  const value = String(raw || "").trim();
  if (!value) return null;

  const browser =
    /Edg\//i.test(value)
      ? "Edge"
      : /Chrome\//i.test(value)
      ? "Chrome"
      : /Firefox\//i.test(value)
      ? "Firefox"
      : /Safari\//i.test(value)
      ? "Safari"
      : "Browser";

  const os =
    /Windows/i.test(value)
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
