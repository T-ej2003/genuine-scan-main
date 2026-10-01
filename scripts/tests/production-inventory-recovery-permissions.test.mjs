import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
const read = (path) => fs.readFileSync(path, "utf8");

test("both inventory recovery transactions have exact-table DynamoDB authority", () => {
  const terraform = read("infra/aws/terraform/production-green-stage-b/main.tf");
  const statement = terraform.match(/Sid\s*=\s*"ClaimOnlyStageBReplayRows"([\s\S]*?)\n\s*}/)?.[1];
  assert.ok(statement);
  const actions = [...statement.matchAll(/"(dynamodb:[A-Za-z]+)"/g)].map((match) => match[1]);
  assert.deepEqual(actions.sort(), ["ConditionCheckItem", "DeleteItem", "GetItem", "PutItem", "TransactWriteItems", "UpdateItem"].map((action) => `dynamodb:${action}`).sort());
  assert.match(statement, /Resource\s*=\s*aws_dynamodb_table\.replay\.arn/);
  assert.doesNotMatch(statement, /Resource\s*=\s*"\*"/);
  const broker = read("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs");
  for (const name of ["preDeploymentRecoveryTransaction", "absentInventoryRecoveryTransaction"]) {
    const body = broker.split(`export function ${name}(`)[1].split("\n}")[0];
    assert.match(body, /ConditionCheck:/);
    for (const item of body.matchAll(/\{ (Put|Update|ConditionCheck):/g)) {
      assert.ok(actions.includes(`dynamodb:${{ Put: "PutItem", Update: "UpdateItem", ConditionCheck: "ConditionCheckItem" }[item[1]]}`));
    }
  }
});
