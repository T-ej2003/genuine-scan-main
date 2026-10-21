import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {conditionalHash,conditionalSha,exactConditionalKeys} from './production-cutover-conditional-authorization.mjs';
import {assertEcsTaskDefinitionReadback} from '../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs';
import {OVERLAP_OPERATION_TAG,OVERLAP_TASK_MARKER} from './production-overlap-task-definition.mjs';

export const CONDITIONAL_EXECUTION_TAG='MSCQRConditionalExecution';
export function authenticateConditionalRegistration({attempt,candidates,auditEvents,censusComplete}) {
  exactConditionalKeys(attempt,['operationId','executionId','request','principal','startedAt','deadline'],'Registration attempt');
  conditionalSha(attempt.operationId); conditionalSha(attempt.executionId);
  assert.equal(censusComplete,true,'Complete paginated census required');
  assert.ok(Array.isArray(candidates)&&candidates.length<=10000&&Array.isArray(auditEvents));
  const start=Date.parse(attempt.startedAt),end=Date.parse(attempt.deadline);
  assert.ok(Number.isFinite(start)&&Number.isFinite(end)&&end>start);
  assert.match(attempt.principal,/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const matches=candidates.filter(value=>value.tags?.some(tag=>tag.key===OVERLAP_OPERATION_TAG&&tag.value===attempt.operationId));
  assert.equal(matches.length,1,'Registration outcome unknown or conflicting; another registration is forbidden');
  const definition=matches[0];
  assert.match(definition.taskDefinitionArn,/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/);
  assert.equal(definition.status,'ACTIVE'); assert.equal(definition.registeredBy,attempt.principal);
  assert.ok(Date.parse(definition.registeredAt)>=start&&Date.parse(definition.registeredAt)<=end,'Registration time is not bound');
  const {tags,...expected}=attempt.request;
  assertEcsTaskDefinitionReadback({definition,taskDefinitionArn:definition.taskDefinitionArn,expected,label:'Conditional registered task'});
  assert.deepEqual([...definition.tags].sort((a,b)=>a.key.localeCompare(b.key)),[...tags].sort((a,b)=>a.key.localeCompare(b.key)),'Exact registration tags differ');
  assert.ok(tags.some(tag=>tag.key===CONDITIONAL_EXECUTION_TAG&&tag.value===attempt.executionId));
  assert.ok(tags.some(tag=>tag.key===OVERLAP_TASK_MARKER.key&&tag.value===OVERLAP_TASK_MARKER.value));
  const native=auditEvents.filter(event=>event.eventSource==='ecs.amazonaws.com'&&event.eventName==='RegisterTaskDefinition'&&!event.errorCode&&event.userIdentity?.arn===attempt.principal
    &&event.responseElements?.taskDefinition?.taskDefinitionArn===definition.taskDefinitionArn&&Date.parse(event.eventTime)>=start&&Date.parse(event.eventTime)<=end);
  assert.equal(native.length,1,'Authoritative unique registration event required');
  assert.ok(native[0].eventID&&native[0].requestID);
  assert.equal(native[0].awsRegion,'eu-west-2'); assert.equal(native[0].recipientAccountId,'368992683803');
  assert.equal(conditionalHash(native[0].requestParameters),conditionalHash(attempt.request),'Native request does not match authorization context');
  return {taskDefinitionArn:definition.taskDefinitionArn,requestID:native[0].requestID,eventID:native[0].eventID,requestSha256:conditionalHash(attempt.request)};
}

const authenticatedProofs=new WeakSet();
export const isAuthenticatedConditionalRegistrationProof=proof=>authenticatedProofs.has(proof);

/** Read-only reconciliation. Delayed/missing CloudTrail evidence remains uncertainty, never permission to register again. */
export async function readConditionalRegistrationProof({attempt,run,now=Date.now(),readTimeoutMs=30000}) {
  assert.equal(typeof run,'function');assert.ok(Number.isSafeInteger(readTimeoutMs)&&readTimeoutMs>0&&readTimeoutMs<=30000,'Bounded reconciliation deadline required');
  assert.ok(Number.isSafeInteger(now));
  const started=performance.now();let responseBytes=0;
  const read=async args=>{
    const remaining=readTimeoutMs-(performance.now()-started);assert.ok(remaining>0,'Registration reconciliation deadline exceeded; outcome remains unknown');let timer;let response;
    try{response=await Promise.race([Promise.resolve().then(()=>run([...args,'--output','json','--no-cli-pager','--region','eu-west-2'])),new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(new Error('Registration reconciliation deadline exceeded; outcome remains unknown')),remaining);})]);}finally{clearTimeout(timer);}
    responseBytes+=Buffer.byteLength(typeof response==='string'?response:JSON.stringify(response));assert.ok(responseBytes<=16*1024*1024,'Registration reconciliation exceeds bounded output');
    return typeof response==='string'?JSON.parse(response):response;
  };
  const identity=await read(['sts','get-caller-identity']);
  assert.equal(identity.Arn,attempt.principal,'Reconciliation identity differs from dispatch');
  const arns=[],seen=new Set();let token;
  do {
    const page=await read(['ecs','list-task-definitions','--family-prefix','mscqr-production-rls-green-backend-candidate','--status','ACTIVE','--no-paginate',...(token?['--next-token',token]:[])]);
    assert.ok(Array.isArray(page.taskDefinitionArns));arns.push(...page.taskDefinitionArns);
    assert.ok(arns.length<=10000 && new Set(arns).size===arns.length,'Task census is duplicate or unbounded');
    token=page.nextToken;
    if(token){assert.ok(typeof token==='string'&&!seen.has(token),'Task census did not advance');seen.add(token);}
  }while(token);
  const candidates=[];
  for(const arn of arns){
    assert.match(arn,/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/);
    const result=await read(['ecs','describe-task-definition','--task-definition',arn,'--include','TAGS']);
    assert.equal(result.taskDefinition.taskDefinitionArn,arn);
    if(result.tags?.some(tag=>tag.key===OVERLAP_OPERATION_TAG&&tag.value===attempt.operationId))candidates.push({...result.taskDefinition,tags:result.tags});
    assert.ok(candidates.length<=1,'Registration outcome conflicting');
  }
  const matched=candidates.filter(value=>value.tags?.some(tag=>tag.key===OVERLAP_OPERATION_TAG&&tag.value===attempt.operationId));
  assert.equal(matched.length,1,'Registration outcome unknown or conflicting');
  const auditEvents=[];seen.clear();token=undefined;
  do {
    const page=await read(['cloudtrail','lookup-events','--lookup-attributes',`AttributeKey=ResourceName,AttributeValue=${matched[0].taskDefinitionArn}`,'--start-time',attempt.startedAt,'--end-time',attempt.deadline,'--no-paginate',...(token?['--next-token',token]:[])]);
    assert.ok(Array.isArray(page.Events));
    for(const event of page.Events){assert.ok(typeof event.CloudTrailEvent==='string'&&event.CloudTrailEvent.length<=1024*1024);auditEvents.push(JSON.parse(event.CloudTrailEvent));}
    assert.ok(auditEvents.length<=10000,'Audit census exceeds limit');token=page.NextToken;
    if(token){assert.ok(typeof token==='string'&&!seen.has(token),'Audit census did not advance');seen.add(token);}
  }while(token);
  const result=authenticateConditionalRegistration({attempt,candidates,auditEvents,censusComplete:true});
  const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
  const proof=freeze({kind:'CUTOVER_AUTHENTICATED_REGISTRATION_V1',attempt:structuredClone(attempt),attemptSha256:conditionalHash(attempt),result,observedAt:now});
  authenticatedProofs.add(proof);return proof;
}
