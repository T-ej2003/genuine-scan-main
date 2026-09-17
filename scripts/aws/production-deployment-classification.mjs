import assert from "node:assert/strict";
import { classifyStageBImageReusePath } from "./validate-stage-b-image-reuse.mjs";

export const PRODUCTION_RELEASE_CLASS = Object.freeze({
  NORMAL_APPLICATION: "NORMAL_APPLICATION",
  SECURITY_INFRASTRUCTURE: "SECURITY_INFRASTRUCTURE",
  EMERGENCY_RECOVERY: "EMERGENCY_RECOVERY",
});

const normalApplication = [
  /^backend\/src\/(?!.*(?:auth|mfa|permission|tenant|security|risk|invite|session|rls))/,
  /^backend\/package(?:-lock)?\.json$/,
  /^package(?:-lock)?\.json$/,
  /^src\//,
  /^public\//,
  /^shared\//,
  /^components\.json$/,
  /^index\.html$/,
  /^postcss\.config\.js$/,
  /^tailwind\.config\.ts$/,
  /^vite\.config\.[^/]+$/,
  /^Dockerfile\.ecs-frontend$/,
  /^docker\/nginx-entrypoint\.sh$/,
  /^\.dockerignore$/,
  /^eslint\.config\.js$/,
  /^nginx\.ecs-frontend\.conf$/,
  /^tsconfig[^/]*\.json$/,
  /^vitest\.config\.[^/]+$/,
];

const securityInfrastructure = [
  /^\.github\/workflows\//,
  /^infra\//,
  /^backend\/prisma\//,
  /^backend\/src\/.*(?:auth|mfa|permission|tenant|security|risk|invite|session|rls)/,
  /^src\/.*(?:auth|mfa|permission|tenant|security|risk|invite|session)/i,
  /(?:^|\/)(?:\.env|.*(?:policy|grant|role|ownership|network|kms|iam|rls|migration|schema))\./i,
  /^documents\/(?:security|ops\/iam)\//,
  /^scripts\/(?:aws|security|check-|validate-)/,
];

const emergencyRecovery = [
  /(?:^|\/)(?:recovery|rebaseline|bootstrap|cutover|rotation)(?:\/|\.|-)/i,
  /(?:^|\/)(?:stage-b|initial-activation)(?:\/|\.|-)/i,
  /^scripts\/aws\/.*(?:recover|rebaseline|bootstrap|cutover|rotation)/i,
];

const validPath = (value) => {
  assert.equal(typeof value, "string");
  assert.ok(/^[\x20-\x7e]+$/.test(value) && !value.startsWith("/") && !value.split("/").includes(".."), `Invalid source path: ${value}`);
};
const matches = (patterns, value) => patterns.some((pattern) => pattern.test(value));

export function classifyProductionChanges(paths) {
  assert.ok(Array.isArray(paths));
  const changed = [...new Set(paths)].sort();
  changed.forEach(validPath);
  if (changed.some((file) => matches(emergencyRecovery, file))) {
    return Object.freeze({ releaseClass: PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY, files: changed, backend: false, frontend: false, worker: false, database: false });
  }
  if (changed.some((file) => matches(securityInfrastructure, file))) {
    return Object.freeze({ releaseClass: PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE, files: changed, backend: false, frontend: false, worker: false, database: changed.some((file) => /^backend\/prisma\//.test(file) || /\.sql$/.test(file)) });
  }
  const unknown = changed.filter((file) => !matches(normalApplication, file) && !/^scripts\/tests?\//.test(file) && !/^backend\/tests?\//.test(file) && !/\.md$/.test(file));
  assert.equal(unknown.length, 0, `Ambiguous production change paths: ${unknown.join(", ")}`);
  const image = changed.map(classifyStageBImageReusePath);
  const backendAffecting = image.some(({ file, imageAffecting }) => imageAffecting && (/^backend\//.test(file) || /^shared\//.test(file)));
  const frontendAffecting = image.some(({ file, imageAffecting }) => imageAffecting && (/^(?:src|public|shared)\//.test(file) || /(?:frontend|web|Dockerfile\.ecs-frontend|\.dockerignore|postcss|tailwind|nginx-entrypoint|index\.html)/i.test(file)));
  const workerAffecting = image.some(({ file, imageAffecting }) => imageAffecting && (/^backend\/(?:src\/.*worker|scripts\/.*worker)/i.test(file) || /^worker\//i.test(file) || /^shared\//.test(file)));
  if (workerAffecting) {
    return Object.freeze({ releaseClass: PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE, files: changed, backend: backendAffecting, frontend: frontendAffecting, worker: true, database: false });
  }
  return Object.freeze({
    releaseClass: PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION,
    files: changed,
    backend: backendAffecting,
    frontend: frontendAffecting,
    worker: workerAffecting,
    database: false,
  });
}

export function assertNormalApplicationRelease(classification) {
  assert.equal(classification?.releaseClass, PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION, "Sensitive or ambiguous changes must not enter the normal deployment lane.");
  return classification;
}
