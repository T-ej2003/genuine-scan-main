// This is a reviewed source-inventory guard, not a generated-artifact value.
// The July 2026 C03/B02 refactor retired 28 unreachable legacy maintenance
// entrypoints (several now resolve to explicit refusing wrappers) while
// retaining their application behavior under registered paths. The reviewed
// B01 contract subsequently restored the previously missing canonical refresh
// workflow, so the source-reconstructable baseline is now 401.
export const EXPECTED_WORKFLOW_COUNT = 401;
export const EXPECTED_CONTEXT_FAMILY_COUNT = 280;
export const EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT = 32;
