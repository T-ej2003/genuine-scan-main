// This is a reviewed source-inventory guard, not a generated-artifact value.
// The final capability migration removed protected access from legacy
// controller/service owners and maps the public support tracker to its exact
// pre-auth repository boundary. Re-scanning protected main after PR #570
// discovers 327 paths; invite activation adds three B01 paths.
// Startex replaces controller table access with scoped repositories, retires
// two telemetry database paths and two obsolete analytics helpers, and adds
// one exact scan projection. The current source census is 327 paths/207 families.
export const EXPECTED_WORKFLOW_COUNT = 327;
export const EXPECTED_CONTEXT_FAMILY_COUNT = 207;
// The existing migration-only bootstrap function is now discovered as its own
// startup call path; it remains contract-only, not an operator table grant.
export const EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT = 25;
