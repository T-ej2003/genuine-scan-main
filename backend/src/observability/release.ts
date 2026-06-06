import packageJson from "../../package.json";

const firstKnownValue = (...values: Array<string | undefined>) => {
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (normalized && normalized.toLowerCase() !== "unknown") return normalized;
  }
  return "unknown";
};

const gitSha = firstKnownValue(
  process.env.RELEASE_GIT_SHA,
  process.env.GITHUB_SHA,
  process.env.COMMIT_SHA,
  process.env.GIT_SHA,
  process.env.RENDER_GIT_COMMIT,
  process.env.VERCEL_GIT_COMMIT_SHA
);

const shortGitSha = gitSha === "unknown" ? "unknown" : gitSha.slice(0, 12);
const release =
  shortGitSha === "unknown"
    ? `${packageJson.name}@${packageJson.version}`
    : `${packageJson.name}@${packageJson.version}+${shortGitSha}`;

export const releaseMetadata = {
  name: packageJson.name,
  version: packageJson.version,
  gitSha,
  shortGitSha,
  release,
  environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",
};
