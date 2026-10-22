import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const policy=JSON.parse(fs.readFileSync('infra/aws/terraform/production-web-release/stage-b-native-audit-policy.json','utf8'));
const statements=policy.Statement;
const actions=statements.flatMap(statement=>Array.isArray(statement.Action)?statement.Action:[statement.Action]);

test('hosted native audit policy grants only the reviewed read surface',()=>{
 assert.equal(policy.Version,'2012-10-17');
 assert.deepEqual([...new Set(actions)].sort(),['cloudtrail:LookupEvents','dynamodb:GetItem','ecs:DescribeTaskDefinition','ecs:DescribeTasks',
  'iam:GetRolePolicy','s3:GetObject','s3:GetObjectVersion','secretsmanager:DescribeSecret','secretsmanager:ListSecretVersionIds'].sort());
 assert.ok(statements.every(statement=>statement.Effect==='Allow'));
 assert.equal(actions.some(action=>/Sign|Put|Update|Register|GetSecretValue|AssumeRole|ExecuteCommand/.test(action)),false);
 const cloudtrail=statements.find(statement=>statement.Sid==='ReadRegionalNativeMutationEvents');
 assert.equal(cloudtrail.Resource,'*');
 assert.equal(cloudtrail.Condition.StringEquals['aws:RequestedRegion'],'eu-west-2');
 const secret=statements.find(statement=>statement.Sid==='ReadProductionRotationSecretVersionMetadata');
 assert.equal(secret.Resource.some(resource=>resource==='*'),false);
 const broker=statements.find(statement=>statement.Sid==='ReadFullRlsOneUseBrokerClaims');
 assert.deepEqual(broker.Condition['ForAllValues:StringLike']['dynamodb:LeadingKeys'],['*#full-rls-*']);
 const main=fs.readFileSync('infra/aws/terraform/production-web-release/main.tf','utf8');
 assert.match(main,/resource "aws_iam_role_policy" "stage_b_native_audit"/);
 assert.match(main,/stage-b-native-audit-policy\.json/);
 const checker=fs.readFileSync('infra/aws/terraform/production-green-stage-a/main.tf','utf8');
 const checkerPolicy=checker.slice(checker.indexOf('resource "aws_iam_role_policy" "checker"'),
  checker.indexOf('resource "aws_iam_role_policy" "checker_assume_target"'));
 for(const action of ['cloudtrail:LookupEvents','s3:GetObject','iam:GetRolePolicy','secretsmanager:DescribeSecret',
  'ecs:DescribeTaskDefinition'])assert.ok(checkerPolicy.includes(action));
 assert.doesNotMatch(checkerPolicy,/secretsmanager:GetSecretValue|ecs:UpdateService|ecs:RegisterTaskDefinition|kms:Decrypt/);
});
