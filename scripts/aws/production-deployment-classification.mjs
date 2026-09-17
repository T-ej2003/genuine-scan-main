import assert from "node:assert/strict";
import { classifyStageBImageReusePath } from "./validate-stage-b-image-reuse.mjs";

export const PRODUCTION_RELEASE_CLASS = Object.freeze({
  NORMAL_APPLICATION: "NORMAL_APPLICATION",
  SECURITY_INFRASTRUCTURE: "SECURITY_INFRASTRUCTURE",
  EMERGENCY_RECOVERY: "EMERGENCY_RECOVERY",
});

// Normal ownership is explicit. Unknown runtime ownership fails closed; security
// ownership is evaluated first and can never be made normal by a filename.
const normalApplication = [
  /^backend\/src\/services\/(?:batchService|qrService|notificationService)\.ts$/,
  /^backend\/src\/printing\//,
  /^backend\/src\/utils\/(?:cursorPagination|email|logger|boundedJson|realtime)\.ts$/,
  /^backend\/package(?:-lock)?\.json$/,
  /^package(?:-lock)?\.json$/,
  /^src\/(?:App\.tsx|main\.tsx|App\.css|index\.css)$/,
  /^src\/(?:components\/(?!auth\/)|features\/batches\/|pages\/(?:Batches|QrBatches)|hooks\/)/,
  /^public\//,
  /^shared\/(?:ui|formatting|validation)\//,
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
  /^backend\/src\/(?:middleware\/(?:auth|rbac|csrf|tenantIsolation|customerVerifyAuth)|security\/|config\/database\.ts|app\.ts)/,
  /^backend\/src\/services\/(?:accessControlService|auth|mfa|session|invitation|role|risk|tenant)/i,
  /^backend\/src\/(?:auth|workers)\//,
  /^backend\/src\/utils\/(?:security|clientIp|mtlsFingerprintHeader|secretConfig|cookies|ipAddress|publicIntegrityGuard|prismaStorageGuard)\.ts$/,
  /^src\/(?:contexts\/|components\/auth\/|features\/(?:auth|mfa|security|account-settings|verify|licensees|manufacturers)\/|pages\/(?:AcceptInvite|ForgotPassword|Login|ResetPassword|Settings|VerifyEmail)|lib\/(?:api(?:\/|\.ts$)|api-client\.ts|browser-storage-cleanup\.ts|secure-printer-readiness\.ts|verification-decision\.ts|webauthn\.ts)|app\/route-metadata)/i,
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
  const unknown = changed.filter((file) => !matches(normalApplication, file) && !/^scripts\/tests?\//.test(file) && !/^backend\/tests?\//.test(file) && !/^src\/test\//.test(file) && !/\.md$/.test(file));
  assert.equal(unknown.length, 0, `Ambiguous production change paths: ${unknown.join(", ")}`);
  const image = changed.map(classifyStageBImageReusePath);
  const backendAffecting = image.some(({ file, imageAffecting }) => imageAffecting && (/^backend\//.test(file) || /^shared\//.test(file)));
  const frontendAffecting = image.some(({ file, imageAffecting }) => imageAffecting && (/^(?:src|public|shared)\//.test(file) || /^(?:package(?:-lock)?\.json|components\.json|eslint\.config\.js|index\.html|postcss\.config\.js|tailwind\.config\.ts|tsconfig(?:\.[^/]+)?\.json|vite\.config\.[^/]+|vitest\.config\.[^/]+|Dockerfile\.ecs-frontend|nginx\.ecs-frontend\.conf|docker\/nginx-entrypoint\.sh|\.dockerignore)$/.test(file)));
  if (image.some(({ imageAffecting }) => imageAffecting) && !backendAffecting && !frontendAffecting) throw new Error("Image-affecting production input has no service owner.");
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

// Component baselines legitimately differ. Classify each component range on
// its own, then select only that component's impact; do not re-deploy backend
// merely because an older backend commit appears in the frontend range.
export function classifyProductionComponentRanges({ backendFiles = [], frontendFiles = [], securityFiles = [], databaseFiles = [] } = {}) {
  const backend = assertNormalApplicationRelease(classifyProductionChanges(backendFiles));
  const frontend = assertNormalApplicationRelease(classifyProductionChanges(frontendFiles));
  const security = classifyProductionChanges(securityFiles);
  const database = classifyProductionChanges(databaseFiles);
  for (const classification of [security, database])
    if (classification.releaseClass !== PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION || classification.worker)
      throw new Error("A stronger-lane component has undeployed production impact.");
  return Object.freeze({
    releaseClass: PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION,
    files: [...new Set([...backend.files, ...frontend.files])].sort(),
    backend: backend.backend,
    frontend: frontend.frontend,
    worker: false,
    database: false,
    componentFiles: Object.freeze({ backend: backend.files, frontend: frontend.files, security: security.files, database: database.files }),
  });
}
