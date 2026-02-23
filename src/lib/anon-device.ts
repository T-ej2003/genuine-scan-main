const DEVICE_COOKIE_NAME = "aq_vid";
const ONE_YEAR_SECONDS = 60 * 60 * 24 * 365;

const parseCookieValue = (cookieName: string) => {
  if (typeof document === "undefined") return "";
  const parts = document.cookie.split(";").map((part) => part.trim());
  const found = parts.find((part) => part.startsWith(`${cookieName}=`));
  return found ? decodeURIComponent(found.split("=").slice(1).join("=")) : "";
};

const makeId = () => {
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 12)}`;
};

const persistCookie = (value: string) => {
  if (typeof document === "undefined") return;
  const secure = typeof window !== "undefined" && window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${DEVICE_COOKIE_NAME}=${encodeURIComponent(value)}; Max-Age=${ONE_YEAR_SECONDS}; Path=/; SameSite=Lax${secure}`;
};

export const getOrCreateAnonDeviceId = () => {
  const existing = parseCookieValue(DEVICE_COOKIE_NAME);
  if (existing) return existing;
  const generated = makeId();
  persistCookie(generated);
  return generated;
};

