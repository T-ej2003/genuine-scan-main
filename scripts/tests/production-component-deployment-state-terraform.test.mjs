import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const root = "infra/aws/terraform/production-component-deployment-state";
const table = "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-component-deployment-state";
const read = (name) => JSON.parse(fs.readFileSync(`${root}/${name}`, "utf8"));

test("component deployment state Terraform fixes the table, key, and exact writer trust", () => {
  const source = fs.readFileSync(`${root}/main.tf`, "utf8");
  assert.match(source, /name\s*=\s*"mscqr-production-component-deployment-state"/);
  assert.match(source, /billing_mode\s*=\s*"PAY_PER_REQUEST"/); assert.match(source, /hash_key\s*=\s*"stateKey"/);
  const trust = read("normal-deployer-trust-policy.json").Statement[0].Condition.StringEquals;
  assert.equal(trust["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production-normal-deploy");
  assert.deepEqual(Object.keys(trust).sort(), ["token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:sub"]);
  const policy = read("normal-deployer-policy.json");
  const backendCandidate = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:*";
  const frontend = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:*";
  const tag = policy.Statement.find(({ Sid }) => Sid === "PreserveTaskDefinitionTags");
  assert.deepEqual(tag.Resource, [backendCandidate, frontend]);
  const register = policy.Statement.find(({ Sid }) => Sid === "RegisterExactFamilies");
  assert.equal(register.Resource, "*");
  assert.deepEqual(register.Condition, { StringEquals: { "aws:RequestedRegion": "eu-west-2" } });
  const frontendRead = policy.Statement.find(({ Sid }) => Sid === "ReadExactFrontendImage");
  assert.deepEqual(frontendRead.Action, ["ecr:DescribeImages", "ecr:DescribeRepositories"]);
});

test("state permissions are exact-key DynamoDB operations and publishers receive no state writer", () => {
  for (const file of ["normal-deployer-policy.json", "bootstrap-policy.json", "release-terminal-state-policy.json"]) {
    const statements = read(file).Statement.filter((statement) => JSON.stringify(statement.Action).includes("dynamodb:"));
    assert.ok(statements.length > 0);
    for (const statement of statements) {
      assert.equal(statement.Resource, table); assert.deepEqual(statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"], ["production#T-ej2003/genuine-scan-main"]);
      assert.doesNotMatch(JSON.stringify(statement.Action), /dynamodb:\*/);
    }
  }
  const publisher = JSON.parse(fs.readFileSync("infra/aws/terraform/production-web-release/publisher-permissions-policy.json", "utf8"));
  assert.doesNotMatch(JSON.stringify(publisher), /dynamodb:/i);
});
