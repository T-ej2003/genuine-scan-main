import assert from 'node:assert/strict';
import test from 'node:test';
import {assertConditionalHumanReview,INDEPENDENT_REVIEW_V1,SOLO_OPERATOR_CONTROLLED_V1,SOLO_OPERATOR_POLICY} from '../aws/production-cutover-human-policy.mjs';
import {PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';

const evidence={repository:'T-ej2003/genuine-scan-main',environment:'production',workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,executionActor:'operator',actualApproval:{userId:7,userLogin:'reviewer'}};
const run={actor:{id:3,login:'operator'}};

test('independent conditional approval requires a different authenticated human, regardless of role or environment self-review setting',()=>{
  assert.equal(assertConditionalHumanReview({evidence,run,phase:'PREPARE_OVERLAP'}).policyVersion,INDEPENDENT_REVIEW_V1);
  assert.throws(()=>assertConditionalHumanReview({evidence:{...evidence,actualApproval:{userId:3,userLogin:'operator'},preventSelfReview:false},run,phase:'PREPARE_OVERLAP'}),/self-reviewed/);
  assert.throws(()=>assertConditionalHumanReview({evidence,run:{actor:{login:'operator'}},phase:'PREPARE_OVERLAP'}),/actor identity/);
  assert.throws(()=>assertConditionalHumanReview({evidence:{...evidence,actualApproval:{}},run,phase:'PREPARE_OVERLAP'}),/reviewer identity/);
});

test('disabled solo policy and unknown modes cannot authorize a phase',()=>{
  assert.equal(SOLO_OPERATOR_POLICY.enabled,false);
  assert.equal(SOLO_OPERATOR_POLICY.repository,PRODUCTION_ENVIRONMENT_APPROVAL.repository);
  assert.equal(SOLO_OPERATOR_POLICY.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef);
  assert.throws(()=>assertConditionalHumanReview({evidence,run,phase:'INVENTORY_ADOPTION',policyVersion:SOLO_OPERATOR_CONTROLLED_V1,d:{}}),/disabled/);
  assert.throws(()=>assertConditionalHumanReview({evidence,run,phase:'INVENTORY_ADOPTION',policyVersion:'UNKNOWN',d:{}}),/Unknown/);
});
