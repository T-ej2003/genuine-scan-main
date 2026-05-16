const requiredPresence = [
  "EMAIL_USE_JSON_TRANSPORT",
  "E2E_EXPOSE_CUSTOMER_OTP",
  "E2E_SUPERADMIN_EMAIL",
  "E2E_SUPERADMIN_PASSWORD",
];

const failures = [];

const hasValue = (name) => String(process.env[name] || "").trim().length > 0;
const isTrue = (name) => String(process.env[name] || "").trim().toLowerCase() === "true";

console.log("E2E preflight:");

if (process.env.NODE_ENV === "test") {
  console.log("- NODE_ENV=test: present");
} else {
  console.log("- NODE_ENV=test: missing");
  failures.push("NODE_ENV must be test");
}

for (const name of requiredPresence) {
  const present = hasValue(name);
  console.log(`- ${name}: ${present ? "present" : "missing"}`);
  if (!present) {
    failures.push(`${name} is required`);
  }
}

for (const name of ["EMAIL_USE_JSON_TRANSPORT", "E2E_EXPOSE_CUSTOMER_OTP"]) {
  if (hasValue(name) && !isTrue(name)) {
    failures.push(`${name} must be true for the Playwright E2E handoff`);
  }
}

if (failures.length > 0) {
  console.error("E2E preflight failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("E2E preflight passed.");
