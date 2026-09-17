// Only the reviewed executable source of these terminal operations is covered.
// Other recovery/bootstrap/Stage-B paths remain sensitive even at an older SHA.
export const COMPLETED_EMERGENCY_PATHS = Object.freeze({
  "backend-health-recovery": Object.freeze([
    "scripts/aws/recover-production-backend-health.mjs",
    "scripts/aws/production-backend-health-recovery-contract.mjs",
    "scripts/aws/dispatch-production-backend-health-recovery.mjs",
    "scripts/aws/commit-production-component-recovery-state.mjs",
  ]),
  "rotation-overlap": Object.freeze([
    "scripts/aws/run-production-cutover.mjs",
    "scripts/aws/production-cutover-control-plane.mjs",
    "scripts/aws/production-cutover-production-adapters.mjs",
    "scripts/aws/production-overlap-readiness-contract.mjs",
    "scripts/aws/commit-production-component-rotation-state.mjs",
  ]),
  "rotation-cleanup": Object.freeze([
    "scripts/aws/run-production-cutover.mjs",
    "scripts/aws/production-cutover-control-plane.mjs",
    "scripts/aws/production-cutover-production-adapters.mjs",
    "scripts/aws/production-overlap-readiness-contract.mjs",
    "scripts/aws/commit-production-component-rotation-state.mjs",
  ]),
});
