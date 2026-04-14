import { spawnSync } from "node:child_process";

const ensurePath = () => {
  const segments = String(process.env.PATH || "")
    .split(":")
    .filter(Boolean);
  for (const entry of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]) {
    if (!segments.includes(entry)) segments.unshift(entry);
  }
  return segments.join(":");
};

const smokeBaseUrl = String(process.env.SMOKE_BASE_URL || "").trim();
if (!smokeBaseUrl) {
  console.error(
    "verify:staging-smoke requires SMOKE_BASE_URL. Set it explicitly so release smoke never falls back to localhost."
  );
  process.exit(1);
}

const run = (cmd, args) => {
  const result = spawnSync(cmd, args, {
    stdio: "inherit",
    env: {
      ...process.env,
      PATH: ensurePath(),
      SMOKE_ALLOW_LOCAL_DEFAULT: "false",
    },
  });
  if (typeof result.status === "number" && result.status !== 0) {
    process.exit(result.status);
  }
  if (result.error) {
    console.error(result.error.message || result.error);
    process.exit(1);
  }
};

run("node", ["scripts/check-staging-smoke-config.mjs"]);
run("node", ["scripts/smoke-release.mjs"]);

