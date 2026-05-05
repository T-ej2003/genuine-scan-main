const publicAuthOptionalPaths = [
  "/",
  "/trust",
  "/privacy",
  "/terms",
  "/cookies",
  "/platform",
  "/request-access",
  "/blog",
  "/connector-download",
  "/verify-email",
  "/help",
  "/help/auth-overview",
  "/help/getting-access",
  "/help/setting-password",
  "/help/roles-permissions",
  "/help/licensee-admin",
  "/help/licensee",
  "/help/manufacturer",
  "/help/customer",
  "/help/support",
] as const;

const publicAuthOptionalPrefixes = [
  "/solutions/",
  "/industries/",
  "/how-scanning-works",
  "/verify",
  "/scan",
] as const;

export const shouldBootstrapCurrentUser = (pathname: string) => {
  const normalized = String(pathname || "/").replace(/\/+$/, "") || "/";
  if (publicAuthOptionalPaths.includes(normalized as (typeof publicAuthOptionalPaths)[number])) return false;
  return !publicAuthOptionalPrefixes.some((prefix) => normalized === prefix.replace(/\/+$/, "") || normalized.startsWith(prefix));
};
