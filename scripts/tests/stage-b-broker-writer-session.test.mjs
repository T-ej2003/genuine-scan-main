import assert from 'node:assert/strict';
import test from 'node:test';
import { writerSession, writerIssuance, writerAccessKeyId } from './fixtures/broker-writer-session.mjs';
import { authenticateBrokerSessionIssuance, proveBrokerWriterUnusable, readBrokerRecoveryAwsClock, createBrokerWriterSessionBoundary,createHostedBrokerWriterSessionBoundary, readBrokerSessionIssuance } from '../aws/stage-b-broker-writer-session.mjs';
const owner = { policyArn: 'exact-policy', owner: 'owner-1', generation: 1, writerSession };
const identity = () => ({ accessKeyIdSha256: writerSession.accessKeyIdSha256, callerArn: writerSession.callerArn, callerUserId: writerSession.callerUserId });
const issuanceWindow = { startTime: '2026-10-03T13:00:00.000Z', endTime: writerSession.expiresAt };
const proof = (record = owner, at = '2026-10-04T01:00:01.000Z', events = [writerIssuance()]) => proveBrokerWriterUnusable(record, {
  readIssuance: s => authenticateBrokerSessionIssuance(events, { accessKeyIdSha256: s.accessKeyIdSha256, callerArn: s.callerArn, callerUserId: s.callerUserId }, { startTime: s.issuedAt, endTime: s.expiresAt }), readClock: () => at });
for (const state of ['active process', 'terminal job with live credentials', 'immediately before expiry', 'exact expiry']) test(`${state} cannot recover`, async () => {
  await assert.rejects(() => proof(owner, state === 'exact expiry' ? writerSession.expiresAt : '2026-10-04T00:59:59.000Z'), /remain usable/);
});
test('authenticated expired session permits recovery without claiming OS process termination', async () => {
  const result = await proof(); assert.equal(result.previousWriterCannotContinue, true); assert.equal(result.processTerminationProven, false);
  assert.notEqual(result.ownerSha256, (await proof({ ...owner, generation: 2 })).ownerSha256);
});
for (const [name, mutate] of [
  ['forged expiry', r => r.writerSession.expiresAt = '2026-10-04T00:30:00.000Z'],
  ['wrong session ARN', r => r.writerSession.callerArn += '-other'],
  ['wrong session key', r => r.writerSession.accessKeyIdSha256 = '0'.repeat(64)],
  ['wrong issue time', r => r.writerSession.issuedAt = '2026-10-03T00:00:00.000Z'],
  ['wrong issuance event', r => r.writerSession.eventId = '22222222-2222-4222-8222-222222222222'],
  ['unbound legacy ownership', r => delete r.writerSession],
]) test(`${name} fails closed`, async () => { const r = structuredClone(owner); mutate(r); await assert.rejects(() => proof(r)); });
for (const [name, mutate] of [
  ['wrong role', e => e.requestParameters.roleArn += '-other'], ['wrong account', e => e.recipientAccountId = '111111111111'],
  ['global/noncanonical region', e => e.awsRegion = 'us-east-1'], ['failed assumption', e => e.errorCode = 'AccessDenied'],
  ['wrong principal', e => e.responseElements.assumedRoleUser.assumedRoleId = 'AROAOTHER:operator'],
  ['unbounded expiry', e => e.responseElements.credentials.expiration = '2026-10-05T00:00:00.000Z'],
  ['wrong session name', e => e.requestParameters.roleSessionName = 'other'],
]) test(`issuance ${name} fails closed`, () => { const e = writerIssuance(); mutate(e); assert.throws(() => authenticateBrokerSessionIssuance([e], identity(), issuanceWindow)); });
const stsClockError = '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>MissingAuthenticationToken</Code></Error></ErrorResponse>';
const clockResponse = (status, url, headers, body = stsClockError, redirected = false) => ({ status, url, redirected, headers: new Headers(headers), text: async () => body });
test('duplicate/ambiguous issuance and untrusted clock metadata fail closed', async () => {
  assert.throws(() => authenticateBrokerSessionIssuance([writerIssuance(), writerIssuance()], identity(), issuanceWindow));
  for (const headers of [{}, { date: 'not a date' }, { date: '0' }, { date: 'Sun, 04 Oct 2026 01:00:01 GMT', age: '2' }]) {
    await assert.rejects(() => readBrokerRecoveryAwsClock(async () => clockResponse(403, 'https://sts.eu-west-2.amazonaws.com/', headers)));
  }
});
test('regional STS HEAD redirect cannot establish the recovery clock', async () => {
  await assert.rejects(() => readBrokerRecoveryAwsClock(async (url, options) => {
    assert.equal(url, 'https://sts.eu-west-2.amazonaws.com/'); assert.equal(options.method, 'POST');
    return clockResponse(302, 'https://aws.amazon.com/iam', { date: 'Sun, 04 Oct 2026 01:00:01 GMT' }, '', true);
  }));
});
test('production clock uses a non-mutating regional STS Query request with redirects and caching disabled', async () => {
  const result = await readBrokerRecoveryAwsClock(async (url, options) => {
    assert.equal(url, 'https://sts.eu-west-2.amazonaws.com/'); assert.equal(options.method, 'POST'); assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store');
    assert.equal(options.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(options.body, 'Action=GetCallerIdentity&Version=2011-06-15');
    return clockResponse(403, url, { date: 'Sun, 04 Oct 2026 01:00:01 GMT' });
  }); assert.equal(result, '2026-10-04T01:00:01.000Z');
});
test('CloudTrail lookup uses the credential-expiration interval and preserves it across pages', () => {
  const calls = [];
  const result = readBrokerSessionIssuance(args => {
    calls.push(args); assert.equal(args[0], 'cloudtrail'); assert.equal(args[1], 'lookup-events'); assert.ok(args.includes('--no-paginate'));
    const assumption = args[args.indexOf('--lookup-attributes') + 1];
    if (!assumption.endsWith('=AssumeRole')) return JSON.stringify({ Events: [] });
    if (!args.includes('--next-token')) return JSON.stringify({ Events: [], NextToken: 'next' });
    return JSON.stringify({ Events: [{ EventId: writerSession.eventId, CloudTrailEvent: JSON.stringify(writerIssuance()) }] });
  }, identity(), issuanceWindow); assert.deepEqual(result, writerSession); assert.equal(calls.length, 4);
  for (const args of calls) {
    assert.equal(args[args.indexOf('--start-time') + 1], issuanceWindow.startTime);
    assert.equal(args[args.indexOf('--end-time') + 1], issuanceWindow.endTime);
  }
  assert.equal(calls[0][calls[0].indexOf('--lookup-attributes') + 1], calls[1][calls[1].indexOf('--lookup-attributes') + 1]);
  assert.ok(calls[1].includes('--next-token'));
});
for (const [name, eventTime] of [['before', '2026-10-03T12:59:59.000Z'], ['after', '2026-10-04T01:00:01.000Z']]) {
  test(`issuance ${name} authenticated interval is rejected`, () => {
    const event = writerIssuance(); event.eventTime = eventTime;
    assert.throws(() => authenticateBrokerSessionIssuance([event], identity(), issuanceWindow), /outside the authenticated interval/);
  });
}
for (const eventName of ['AssumeRole', 'AssumeRoleWithWebIdentity', 'AssumeRoleWithSAML']) {
  test(`${eventName} writer issuance is authenticated`, () => {
    const event = writerIssuance(); event.eventName = eventName;
    assert.deepEqual(authenticateBrokerSessionIssuance([event], identity(), issuanceWindow), writerSession);
  });
}
test('bounded CloudTrail pagination still fails closed at the safety cap', () => {
  let calls = 0;
  assert.throws(() => readBrokerSessionIssuance(args => {
    calls++;
    if (!args[args.indexOf('--lookup-attributes') + 1].endsWith('=AssumeRole')) return JSON.stringify({ Events: [] });
    return JSON.stringify({ Events: [], NextToken: `next-${calls}` });
  }, identity(), issuanceWindow), /search incomplete/);
  assert.equal(calls, 100);
});
test('an issuance for another access key cannot match', () => {
  const event = writerIssuance(); event.responseElements.credentials.accessKeyId = 'ASIA' + 'B'.repeat(16);
  assert.throws(() => authenticateBrokerSessionIssuance([event], identity(), issuanceWindow), /Missing\/ambiguous/);
});
test('missing or overlong authenticated issuance interval fails closed', () => {
  assert.throws(() => readBrokerSessionIssuance(() => '{}', identity()), /Authenticated issuance interval/);
  assert.throws(() => readBrokerSessionIssuance(() => '{}', identity(), { startTime: '2026-10-03T12:59:59.000Z', endTime: writerSession.expiresAt }), /authenticated issuance interval/);
});
test('writer pins credentials once; profile/session refresh cannot extend mutation authority', () => {
  let exported = 0; const events = writerIssuance(), lookups = [];
  const boundary = createBrokerWriterSessionBoundary({ env: { PATH: process.env.PATH, HOME: '/test', AWS_PROFILE: 'untrusted' },
    independentRun: args => {
      if (args[0] === 'sts') return JSON.stringify({ Account: '368992683803', Arn: 'arn:aws:iam::368992683803:user/mscqr-ops-admin' });
      lookups.push(args);
      return JSON.stringify({ Events: args[args.indexOf('--lookup-attributes') + 1].endsWith('=AssumeRole') ? [{ EventId: events.eventID, CloudTrailEvent: JSON.stringify(events) }] : [] });
    },
    exec: (_, args, options) => {
      if (args[0] === 'configure') { exported++; assert.equal(options.env.AWS_PROFILE, 'mscqr-production-release-deployer'); return JSON.stringify({ AccessKeyId: writerAccessKeyId, SecretAccessKey: 'fixture-only', SessionToken: 'fixture-only', Expiration: writerSession.expiresAt }); }
      assert.equal(options.env.AWS_MAX_ATTEMPTS, '1'); assert.equal(options.env.AWS_RETRY_MODE, 'standard'); assert.equal(options.env.AWS_ACCESS_KEY_ID, writerAccessKeyId); assert.equal(options.env.AWS_PROFILE, undefined); assert.equal(options.env.AWS_ROLE_ARN, undefined);
      return JSON.stringify({ Account: '368992683803', Arn: writerSession.callerArn, UserId: writerSession.callerUserId });
    } });
  const pinned = boundary.pin(); pinned.run(['sts', 'get-caller-identity']); pinned.run(['sts', 'get-caller-identity']);
  assert.throws(() => pinned.run(['sts', 'assume-role']), /another session/); assert.throws(() => pinned.run(['iam', 'get-policy', '--profile', 'other']), /redirected/);
  assert.equal(exported, 1); assert.deepEqual(pinned.session, writerSession); assert.equal(pinned.environment.AWS_PROFILE, undefined);
  assert.equal(lookups[0][lookups[0].indexOf('--start-time') + 1], '2026-10-03T13:00:00.000Z');
  assert.equal(lookups[0][lookups[0].indexOf('--end-time') + 1], writerSession.expiresAt);
});
test('pinned credentials must match the independently authenticated expiry', () => {
  const events = writerIssuance();
  const boundary = createBrokerWriterSessionBoundary({ env: { PATH: process.env.PATH, HOME: '/test' },
    independentRun: args => args[0] === 'sts' ? JSON.stringify({ Account: '368992683803', Arn: 'arn:aws:iam::368992683803:user/mscqr-ops-admin' }) : JSON.stringify({ Events: args[args.indexOf('--lookup-attributes') + 1].endsWith('=AssumeRole') ? [{ EventId: events.eventID, CloudTrailEvent: JSON.stringify(events) }] : [] }),
    exec: (_, args) => args[0] === 'configure'
      ? JSON.stringify({ AccessKeyId: writerAccessKeyId, SecretAccessKey: 'fixture-only', SessionToken: 'fixture-only', Expiration: '2026-10-04T02:00:00.000Z' })
      : JSON.stringify({ Account: '368992683803', Arn: writerSession.callerArn, UserId: writerSession.callerUserId }) });
  assert.throws(() => boundary.pin(), /differs from authenticated STS issuance/);
});

test('malformed or conflicting CloudTrail responses never expose session-token contents', () => {
  const secret = 'fixture-token-never-print';
  assert.throws(() => readBrokerSessionIssuance(() => '{"secret":"' + secret, identity(), issuanceWindow), error => !String(error).includes(secret));
  const a = writerIssuance(), b = writerIssuance(); a.responseElements.credentials.sessionToken = secret; b.responseElements.credentials.sessionToken = 'different';
  assert.throws(() => readBrokerSessionIssuance(() => JSON.stringify({ Events: [a,b].map(e => ({ EventId: e.eventID, CloudTrailEvent: JSON.stringify(e) })) }), identity(), issuanceWindow), error => String(error).includes('Conflicting') && !String(error).includes(secret));
});

test('hosted writer pins OIDC credentials and requires exact completed run plus AWS expiry before recovery',async()=>{
  const runId='700',sourceSha='a'.repeat(40),expiration='2026-10-08T13:00:00.000Z';
  const env={PATH:process.env.PATH,HOME:'/test',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
    GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',
    GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:runId,GITHUB_SHA:sourceSha,AWS_ACCESS_KEY_ID:writerAccessKeyId,
    AWS_SECRET_ACCESS_KEY:'fixture-only',AWS_SESSION_TOKEN:'fixture-only',AWS_CREDENTIAL_EXPIRATION:expiration};
  const response={id:700,repository:{full_name:env.GITHUB_REPOSITORY},head_repository:{full_name:env.GITHUB_REPOSITORY},
    path:'.github/workflows/release-train.yml',head_sha:sourceSha,event:'workflow_dispatch',run_attempt:1,status:'in_progress'};
  let observedAt='2026-10-08T12:59:59.000Z';
  const boundary=createHostedBrokerWriterSessionBoundary({env,now:()=>new Date('2026-10-08T12:00:00.000Z'),
    exec:(_,args,options)=>{assert.equal(options.env.AWS_ACCESS_KEY_ID,writerAccessKeyId);assert.equal(options.env.AWS_PROFILE,undefined);
      return JSON.stringify({Account:'368992683803',Arn:`arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/release-${runId}`,
        UserId:`AROAABCDEFGHIJKLMNOP:release-${runId}`});},
    githubRun:args=>{assert.equal(args[1],`repos/T-ej2003/genuine-scan-main/actions/runs/${runId}/attempts/1`);return JSON.stringify(response);},clock:async()=>observedAt});
  const pinned=boundary.pin(),owner={writerSession:pinned.session,operationIdentity:'b'.repeat(64)};
  assert.equal(pinned.session.mechanism,'GITHUB_OIDC_BOUNDED_WRITER');
  assert.throws(()=>pinned.run(['sts','assume-role']),/another session/);
  await assert.rejects(()=>boundary.prove(owner),/may still be running/);
  response.status='completed';await assert.rejects(()=>boundary.prove(owner),/remain usable/);
  observedAt='2026-10-08T13:00:01.000Z';
  const proof=await boundary.prove(owner);assert.equal(proof.mechanism,'GITHUB_RUN_COMPLETED_STS_EXPIRY');
  assert.equal(proof.processTerminationProven,true);assert.equal(proof.previousWriterCannotContinue,true);
  const resumed=createHostedBrokerWriterSessionBoundary({env:{...env,GITHUB_RUN_ATTEMPT:'2',AWS_CREDENTIAL_EXPIRATION:'2026-10-08T14:00:00.000Z'},
    now:()=>new Date('2026-10-08T13:01:00.000Z'),
    exec:()=>JSON.stringify({Account:'368992683803',Arn:`arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/release-${runId}`,
      UserId:`AROAABCDEFGHIJKLMNOP:release-${runId}`}),
    githubRun:args=>{assert.equal(args[1],`repos/T-ej2003/genuine-scan-main/actions/runs/${runId}/attempts/1`);return JSON.stringify(response);},
    clock:async()=>observedAt});
  assert.equal(resumed.pin().session.workflowRunAttempt,'2');
  assert.equal((await resumed.prove(owner)).session.workflowRunAttempt,'1');
  response.head_sha='f'.repeat(40);await assert.rejects(()=>boundary.prove(owner));
  assert.throws(()=>boundary.proveAliasCas({}),/lacks authenticated native execution evidence/);
});
