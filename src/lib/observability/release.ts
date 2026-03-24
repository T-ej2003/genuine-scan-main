export type FrontendReleaseMeta = {
  name: string;
  version: string;
  gitSha: string;
  shortGitSha: string;
  environment: string;
  release: string;
};

const environment = String(import.meta.env.VITE_APP_ENV || import.meta.env.MODE || "development").trim() || "development";
const appName = typeof __APP_NAME__ !== "undefined" ? __APP_NAME__ : "genuine-scan-console";
const appVersion = typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "0.0.0";
const gitSha = String(typeof __APP_GIT_SHA__ !== "undefined" ? __APP_GIT_SHA__ : "unknown").trim() || "unknown";
const shortGitSha = gitSha === "unknown" ? "unknown" : gitSha.slice(0, 12);
const appRelease =
  typeof __APP_RELEASE__ !== "undefined" ? __APP_RELEASE__ : `${appName}@${appVersion}`;

export const frontendRelease: FrontendReleaseMeta = {
  name: appName,
  version: appVersion,
  gitSha,
  shortGitSha,
  environment,
  release: appRelease,
};

if (typeof window !== "undefined") {
  window.__MSCQR_RELEASE__ = frontendRelease;
}
