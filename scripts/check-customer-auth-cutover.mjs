const normalize = (value) => String(value || "").trim();
const parseBool = (value, fallback = false) => {
  const normalized = normalize(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const enforce = parseBool(process.env.ENFORCE_BEARER_COMPAT_DISABLE, false);
const compatible = parseBool(process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED, true);

if (!enforce) {
  console.log("Customer auth cutover check skipped (ENFORCE_BEARER_COMPAT_DISABLE is false).");
  process.exit(0);
}

if (compatible) {
  console.error(
    "Customer auth cutover check failed: VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED must be false when ENFORCE_BEARER_COMPAT_DISABLE=true."
  );
  process.exit(1);
}

console.log("Customer auth cutover check passed.");

