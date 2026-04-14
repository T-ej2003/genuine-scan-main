const normalize = (value) => String(value || "").trim();
const parseBool = (value, fallback = false) => {
  const normalized = normalize(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const rotationWindowComplete = parseBool(process.env.ROTATION_WINDOW_COMPLETE, false);

if (!rotationWindowComplete) {
  console.log("Rotation cleanup check skipped (ROTATION_WINDOW_COMPLETE is false).");
  process.exit(0);
}

const previousKeys = [
  "JWT_SECRET_PREVIOUS",
  "QR_SIGN_HMAC_SECRET_PREVIOUS",
  "PRINTER_SSE_SIGN_SECRET_PREVIOUS",
  "TOKEN_HASH_SECRET_PREVIOUS",
  "INCIDENT_HASH_SALT_PREVIOUS",
  "IP_HASH_SALT_PREVIOUS",
];

const populated = previousKeys.filter((key) => normalize(process.env[key]));
if (populated.length > 0) {
  console.error("Rotation cleanup check failed: previous-slot secrets are still configured.");
  for (const key of populated) {
    console.error(`- ${key}`);
  }
  process.exit(1);
}

console.log("Rotation cleanup check passed.");

