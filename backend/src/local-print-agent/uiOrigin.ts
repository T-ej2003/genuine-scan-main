const DEFAULT_UI_ORIGINS = [
  "https://www.mscqr.com",
  "https://mscqr.com",
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:4173",
  "http://127.0.0.1:4173",
];

const canonicalUiOrigin = (origin: string) => {
  if (/[\\\s*]/.test(origin)) return false;
  try {
    const url = new URL(origin);
    return (url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) &&
      !url.username && !url.password && !url.search && !url.hash && origin === url.origin;
  } catch { return false; }
};

export const isAuthorizedConnectorUiOrigin = (origin: string | undefined, additionalOrigins = process.env.PRINT_AGENT_ALLOWED_ORIGINS) => {
  if (!origin) return true; // Native installer and local command-line requests do not send a browser Origin.
  if (!canonicalUiOrigin(origin)) return false;
  const allowed = [
    ...DEFAULT_UI_ORIGINS,
    process.env.PRINT_AGENT_WEB_APP_ORIGIN,
    ...String(additionalOrigins || "").split(",").map((value) => value.trim()),
  ];
  return allowed.some((value) => value === origin && canonicalUiOrigin(value));
};
