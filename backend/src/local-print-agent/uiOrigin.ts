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

export const isAuthorizedConnectorUiOrigin = (origin: string | undefined, additionalOrigins = process.env.PRINT_AGENT_ALLOWED_ORIGINS) => {
  if (!origin) return true; // Native installer and local command-line requests do not send a browser Origin.
  const allowed = [...DEFAULT_UI_ORIGINS, ...String(additionalOrigins || "").split(",").map((value) => value.trim()).filter(Boolean)];
  return allowed.includes(origin);
};
