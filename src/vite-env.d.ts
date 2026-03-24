/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_API_PROXY_TARGET?: string;
  readonly VITE_GOOGLE_OAUTH_URL?: string;
  readonly VITE_APP_ENV?: string;
  readonly VITE_SENTRY_DSN?: string;
  readonly VITE_SENTRY_SAMPLE_RATE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare const __APP_NAME__: string;
declare const __APP_VERSION__: string;
declare const __APP_GIT_SHA__: string;
declare const __APP_RELEASE__: string;

interface Window {
  __MSCQR_RELEASE__?: {
    name: string;
    version: string;
    gitSha: string;
    shortGitSha: string;
    environment: string;
    release: string;
  };
}
