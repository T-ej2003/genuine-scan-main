export function normalizeWebAppBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw || /[\\\s*%"^&|<>!()]/.test(raw)) throw new Error("WEB_APP_BASE_URL must be a safe web-app URL.");
  let url;
  try { url = new URL(raw); } catch { throw new Error("WEB_APP_BASE_URL is malformed."); }
  const loopback = ["localhost", "127.0.0.1"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || raw.includes("?") || raw.includes("#")) {
    throw new Error("WEB_APP_BASE_URL must use HTTPS (or loopback HTTP) without credentials, query or fragment.");
  }
  return { baseUrl: url.href.replace(/\/+$/, ""), origin: url.origin };
}
