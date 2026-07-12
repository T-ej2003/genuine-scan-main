import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { STAGING_DATABASE_ROLE_CONTEXT as C, assertDatabaseRoleOperatorIdentity } from "../lib/staging-database-role-credentials-core.mjs";
import { createBrokerHandler, fixedRunTaskRequest, validateBrokerEvent } from "../../infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs";

const files = {
  trust: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_TRUST_POLICY_2026-07-12.json",
  assume: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_ASSUME_ROLE_POLICY_2026-07-12.json",
  role: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_POLICY_2026-07-12.json",
};
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const runCheck = (mutate = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-db-role-operator-iam-"));
  const env = { ...process.env };
  try {
    for (const [key, file] of Object.entries(files)) {
      const policy = read(file);
      mutate[key]?.(policy);
      const fixture = path.join(directory, `${key}.json`);
      fs.writeFileSync(fixture, JSON.stringify(policy), { mode: 0o600 });
      env[`MSCQR_STAGING_DATABASE_ROLE_OPERATOR_${key === "role" ? "POLICY" : key === "assume" ? "ASSUME_POLICY" : "TRUST_POLICY"}_PATH`] = fixture;
    }
    return spawnSync("node", ["scripts/check-staging-database-role-operator-iam.mjs"], { encoding: "utf8", env });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const output = (result) => `${result.stdout}\n${result.stderr}`;
const operatorIdentity = { Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${C.operatorRole}/reviewed-session` };

test("reviewed database-role operator IAM templates pass", () => { const result = runCheck(); assert.equal(result.status, 0, output(result)); });
test("human operator has no RunTask PassRole or Secrets Manager access and invokes only the exact broker", () => { const policy=read(files.role); const actions=policy.Statement.flatMap((statement)=>Array.isArray(statement.Action)?statement.Action:[statement.Action]); assert(!actions.includes("ecs:RunTask")); assert(!actions.includes("iam:PassRole")); assert(!actions.some((action)=>action.startsWith("secretsmanager:"))); const invoke=policy.Statement.find((statement)=>statement.Action==="lambda:InvokeFunction"); assert.equal(invoke.Resource,`arn:aws:lambda:${C.region}:${C.accountId}:function:${C.brokerFunction}`); });
test("operator wildcard or production broker resources are rejected", async (t) => { for (const resource of ["*",`arn:aws:lambda:${C.region}:${C.accountId}:function:mscqr-production-database-role-executor-broker`]) await t.test(resource,()=>{ const result=runCheck({role:(policy)=>{policy.Statement.find((statement)=>statement.Action==="lambda:InvokeFunction").Resource=resource;}}); assert.notEqual(result.status,0); assert.match(output(result),/exact staging|production-looking/); }); });
test("trust rejects root wildcard and Terraform plan or apply principals", async (t) => { for (const principal of [`arn:aws:iam::${C.accountId}:root`, "*", `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-plan-role`, `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-apply-role`]) await t.test(principal, () => { const result = runCheck({ trust: (policy) => { policy.Statement[0].Principal.AWS = principal; } }); assert.notEqual(result.status, 0); assert.match(output(result), /Trust policy|forbidden/); }); });
test("trust requires MFA", () => { const result = runCheck({ trust: (policy) => { delete policy.Statement[0].Condition; } }); assert.notEqual(result.status, 0); assert.match(output(result), /require MFA/); });
test("only the dedicated assumed role can execute probe provision or verify", () => { assert.doesNotThrow(() => assertDatabaseRoleOperatorIdentity(operatorIdentity, { AWS_REGION: C.region })); for (const role of ["mscqr-staging-terraform-plan-role", "mscqr-staging-terraform-apply-role", "mscqr-staging-broad-operator"]) assert.throws(() => assertDatabaseRoleOperatorIdentity({ Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${role}/session` }, { AWS_REGION: C.region }), /require assumed role/); });

const brokerConfig={clusterArn:`arn:aws:ecs:${C.region}:${C.accountId}:cluster/${C.cluster}`,taskDefinitionArn:`arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-database-role-admin:7`,subnets:["subnet-private-a","subnet-private-b"],securityGroups:["sg-staging-ecs"]};
test("broker accepts only probe provision and verify",()=>{ for(const mode of ["probe","provision","verify"]) assert.equal(validateBrokerEvent({mode}),mode); for(const mode of ["cutover","rollback","",null]) assert.throws(()=>validateBrokerEvent({mode}),/Mode must/); });
test("broker rejects extra fields and caller-controlled overrides",()=>{ for(const key of ["command","environment","networkConfiguration","taskDefinition","roles","count","launchType","platformVersion","tags","overrides"]) assert.throws(()=>validateBrokerEvent({mode:"probe",[key]:{}}),/exactly one field/); });
test("broker constructs one immutable Fargate request",()=>{ const request=fixedRunTaskRequest("verify",brokerConfig); assert.deepEqual(request,{cluster:brokerConfig.clusterArn,taskDefinition:brokerConfig.taskDefinitionArn,launchType:"FARGATE",count:1,networkConfiguration:{awsvpcConfiguration:{subnets:brokerConfig.subnets,securityGroups:brokerConfig.securityGroups,assignPublicIp:"DISABLED"}},overrides:{containerOverrides:[{name:"db-admin",environment:[{name:"MSCQR_VPC_EXECUTOR_MODE",value:"verify"}]}]}}); });
test("broker returns only sanitized task metadata",async()=>{ const taskArn=`arn:aws:ecs:${C.region}:${C.accountId}:task/${C.cluster}/fixture`; const handler=createBrokerHandler({config:brokerConfig,runTask:async()=>({tasks:[{taskArn}],failures:[]})}); assert.deepEqual(await handler({mode:"probe"}),{status:"started",taskArn}); });
test("broker Terraform role keeps RunTask and PassRole exact and secret-free",()=>{ const source=fs.readFileSync("infra/terraform/staging-api/main.tf","utf8"); const policy=source.match(/resource "aws_iam_role_policy" "database_role_executor_broker"[\s\S]*?(?=\nresource "aws_lambda_function")/)?.[0]||""; assert.match(policy,/task-definition\/mscqr-staging-database-role-admin:\*/); assert.match(policy,/ecs:cluster.*aws_ecs_cluster\.staging\.arn/); assert.match(policy,/aws_iam_role\.database_role_admin_task\.arn, aws_iam_role\.ecs_execution\.arn/); assert.match(policy,/iam:PassedToService.*ecs-tasks\.amazonaws\.com/); assert.doesNotMatch(policy,/Resource\s*=\s*"\*"|secretsmanager:GetSecretValue/); });
test("controller never invokes ECS RunTask directly",()=>{ const source=fs.readFileSync("scripts/aws/staging-database-role-credentials.mjs","utf8"); assert.doesNotMatch(source,/\["ecs",\s*"run-task"/); assert.match(source,/\["lambda",\s*"invoke"/); });
