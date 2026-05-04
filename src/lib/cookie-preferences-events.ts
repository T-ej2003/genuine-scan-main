export const COOKIE_PREFERENCES_OPEN_EVENT = "mscqr:cookie-preferences-open";

export const openCookiePreferences = () => {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(COOKIE_PREFERENCES_OPEN_EVENT));
};
