import packageJson from "../../package.json";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const firstKnownValue = (...values: Array<string | undefined>) => {
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (normalized && normalized.toLowerCase() !== "unknown") return normalized;
  }
  return "unknown";
};

const deploymentGitSha = firstKnownValue(
  process.env.RELEASE_GIT_SHA,
  process.env.GITHUB_SHA,
  process.env.COMMIT_SHA,
  process.env.GIT_SHA,
  process.env.RENDER_GIT_COMMIT,
  process.env.VERCEL_GIT_COMMIT_SHA
);

const imageGitSha = (() => {
  try {
    const metadata = JSON.parse(readFileSync(resolve(__dirname, "../../image-source.json"), "utf8"));
    return typeof metadata.gitSha === "string" && /^[0-9a-f]{40}$/.test(metadata.gitSha)
      ? metadata.gitSha : "unknown";
  } catch {
    return "unknown";
  }
})();
// Runtime deployment variables are not evidence of the source baked into an image.
const gitSha = imageGitSha !== "unknown" ? imageGitSha
  : process.env.NODE_ENV === "production" ? "unknown" : deploymentGitSha;

const shortGitSha = gitSha === "unknown" ? "unknown" : gitSha.slice(0, 12);
const release =
  shortGitSha === "unknown"
    ? `${packageJson.name}@${packageJson.version}`
    : `${packageJson.name}@${packageJson.version}+${shortGitSha}`;

export const releaseMetadata = {
  name: packageJson.name,
  version: packageJson.version,
  gitSha,
  imageGitSha,
  deploymentGitSha,
  shortGitSha,
  release,
  environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",
};
