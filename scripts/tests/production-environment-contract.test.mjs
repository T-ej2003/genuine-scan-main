import assert from "node:assert/strict";
import test from "node:test";
import { assertProductionEnvironmentContract, assertProductionEnvironmentRepository } from "../ci/production-environment-contract.mjs";

const environment = {
  name: "production",
  protection_rules: [{ type: "required_reviewers", reviewers: [{ login: "reviewer" }] }],
  deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
};

test("production requires reviewer approval and exactly main branch", () => {
  assert.deepEqual(assertProductionEnvironmentContract({ environment, branchPolicies: [{ id: 1, name: "main", type: "branch" }] }).branchPolicies, [{ name: "main", type: "branch" }]);
  for (const branchPolicies of [[], [{ name: "develop", type: "branch" }], [{ name: "main", type: "branch" }, { name: "release/*", type: "branch" }]]) assert.throws(() => assertProductionEnvironmentContract({ environment, branchPolicies }));
  assert.throws(() => assertProductionEnvironmentContract({ environment: { ...environment, protection_rules: [] }, branchPolicies: [{ name: "main", type: "branch" }] }));
  assert.throws(() => assertProductionEnvironmentContract({ environment: { ...environment, name: "staging" }, branchPolicies: [{ name: "main", type: "branch" }] }));
});

test("environment readback is bound to this repository", () => {
  assert.doesNotThrow(() => assertProductionEnvironmentRepository("T-ej2003/genuine-scan-main"));
  assert.throws(() => assertProductionEnvironmentRepository("attacker/repository"));
});
