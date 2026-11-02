import assert from 'node:assert/strict';
import { STAGE_B_TASK_DEFINITION_FAMILIES } from './stage-b-reference-audit-contract.mjs';
import { B03_TASK_ADDRESS } from './production-b03-plan-contract.mjs';
export const B03_TASK_FAMILY = 'mscqr-production-b03-incremental';
export const isB03TaskArn = value => /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b03-incremental:[1-9][0-9]*$/.test(value || '');
export const taskRegistrationFamily = address => address === B03_TASK_ADDRESS ? B03_TASK_FAMILY : STAGE_B_TASK_DEFINITION_FAMILIES[address];
const base = () => Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).sort();
export function registrationAddressesFromPlan(plan) {
  return [...base(), ...(plan.variables?.b03_executor_definition_json?.value != null ? [B03_TASK_ADDRESS] : [])].sort();
}
export function registrationAddressesFromDefinitions(definitions) {
  assert.ok(definitions && typeof definitions === 'object' && !Array.isArray(definitions));
  const expected = [...base(), ...(Object.hasOwn(definitions, B03_TASK_ADDRESS) ? [B03_TASK_ADDRESS] : [])].sort();
  assert.deepEqual(Object.keys(definitions).sort(), expected, 'Incomplete or unknown registration definition');
  if (definitions[B03_TASK_ADDRESS]) assert.ok(isB03TaskArn(definitions[B03_TASK_ADDRESS].arn), 'Invalid registered B03 revision');
  return expected;
}
export function brokerRegisteredTaskArns(taskMap, definitions) {
  const arns = Object.keys(taskMap).sort().map(mode => taskMap[mode]);
  if (definitions) {
    registrationAddressesFromDefinitions(definitions);
    if (definitions[B03_TASK_ADDRESS]) arns.push(definitions[B03_TASK_ADDRESS].arn);
  }
  return arns;
}
