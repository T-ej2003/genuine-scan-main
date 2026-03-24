export type FrontendReleaseMeta = {
  name: string;
  version: string;
  gitSha: string;
  shortGitSha: string;
  environment: string;
  release: string;
};

const environment = String(import.meta.env.VITE_APP_ENV || import.meta.env.MODE || "development").trim() || "development";
const gitSha = String(__APP_GIT_SHA__ || "unknown").trim() || "unknown";
const shortGitSha = gitSha === "unknown" ? "unknown" : gitSha.slice(0, 12);

export const frontendRelease: FrontendReleaseMeta = {
  name: __APP_NAME__,
  version: __APP_VERSION__,
  gitSha,
  shortGitSha,
  environment,
  release: __APP_RELEASE__ || `${__APP_NAME__}@${__APP_VERSION__}`,
};

if (typeof window !== "undefined") {
  window.__MSCQR_RELEASE__ = frontendRelease;
}
