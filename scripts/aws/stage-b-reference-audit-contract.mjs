export const STAGE_B_TASK_DEFINITION_FAMILIES = Object.freeze({
  'aws_ecs_task_definition.candidate["backend"]': "mscqr-production-rls-green-backend-candidate",
  'aws_ecs_task_definition.candidate["worker"]': "mscqr-production-rls-green-worker-candidate",
  'aws_ecs_task_definition.candidate["canary"]': "mscqr-production-full-rls-green-application-canary",
  'aws_ecs_task_definition.candidate["read_only_canary"]': "mscqr-production-full-rls-green-read-only-canary",
  'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]': "mscqr-production-full-rls-green-full-rls-admin-bootstrap",
  'aws_ecs_task_definition.executor["full-rls-admin-ownership"]': "mscqr-production-full-rls-green-full-rls-admin-ownership",
  'aws_ecs_task_definition.executor["full-rls-capability-preflight"]': "mscqr-production-full-rls-green-full-rls-capability-preflight",
  'aws_ecs_task_definition.executor["full-rls-role-provision"]': "mscqr-production-full-rls-green-full-rls-role-provision",
  'aws_ecs_task_definition.executor["full-rls-role-verify"]': "mscqr-production-full-rls-green-full-rls-role-verify",
  'aws_ecs_task_definition.executor["full-rls-rollback"]': "mscqr-production-full-rls-green-full-rls-rollback",
  'aws_ecs_task_definition.executor["full-rls-runtime-policy"]': "mscqr-production-full-rls-green-full-rls-runtime-policy",
  'aws_ecs_task_definition.executor["full-rls-verification"]': "mscqr-production-full-rls-green-full-rls-verification",
});

export const STAGE_B_TASK_DEFINITION_FAMILY_NAMES = Object.freeze(
  [...new Set(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES))].sort(),
);

export const STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION = 1;
