import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertComponentIamEnvironment, componentIamAuthorization as contract } from "../aws/component-iam-authorization.mjs";

function fixture() {
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  return {
    config: { id: 91, name: contract.environment, can_admins_bypass: false,
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
      protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] },
    approvals: [{ state: "approved", user: { ...actor }, environments: [{ id: 91, name: contract.environment }] }],
  };
}
const check = f => assertComponentIamEnvironment(f.config, f.branches, f.approvals);
test("exact solo human approval accepted", () => assert.equal(check(fixture()), 91));
const changes = {
  "self review disabled incorrectly": f => { f.config.protection_rules[0].prevent_self_review = true; },
  "admin bypass": f => { f.config.can_admins_bypass = true; },
  "wrong reviewer": f => { f.config.protection_rules[0].reviewers[0].reviewer.id = 1; },
  "different admin reviewer": f => { f.config.protection_rules[0].reviewers[0].reviewer = { type: "User", login: "other-admin", id: 1, site_admin: true }; },
  "team reviewer": f => { f.config.protection_rules[0].reviewers[0].type = "Team"; },
  "empty reviewers": f => { f.config.protection_rules[0].reviewers = []; },
  "no approval": f => { f.approvals = []; },
  "different approving user": f => { f.approvals[0].user.id = 1; },
  "duplicate approval": f => { f.approvals.push(f.approvals[0]); },
  "rejection": f => { f.approvals[0].state = "rejected"; },
  "different environment": f => { f.approvals[0].environments[0].name = "other"; },
  "recreated environment": f => { f.approvals[0].environments[0].id = 92; },
  "non-main branch": f => { f.branches.branch_policies[0].name = "other"; },
  "wildcard branch": f => { f.branches.branch_policies[0].name = "*"; },
  "tag": f => { f.branches.branch_policies[0].type = "tag"; },
  "truncated branches": f => { f.branches.total_count = 2; },
  "all protected branches": f => { f.config.deployment_branch_policy = { protected_branches: true, custom_branch_policies: false }; },
};
for (const [name, mutate] of Object.entries(changes)) test(`environment rejects ${name}`, () => { const f = fixture(); mutate(f); assert.throws(() => check(f)); });
test("authorization dispatch uses the fixed reusable publisher, not arbitrary workflow code", () => {
  const source = fs.readFileSync(".github/workflows/authorize-component-iam-installation.yml", "utf8");
  assert(source.includes("uses: ./.github/workflows/component-iam-authorization-publisher.yml"));
  assert(!source.includes("pull_request_target"));
});
