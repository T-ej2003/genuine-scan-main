import packageJson from "../../package.json";

const gitSha =
  process.env.GIT_SHA ||
  process.env.GITHUB_SHA ||
  process.env.COMMIT_SHA ||
  process.env.RENDER_GIT_COMMIT ||
  process.env.VERCEL_GIT_COMMIT_SHA ||
  "unknown";

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
