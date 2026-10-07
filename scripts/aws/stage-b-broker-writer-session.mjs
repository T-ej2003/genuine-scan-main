import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { brokerAliasIdentity, brokerDigest } from './stage-b-staged-broker-contract.mjs';
import { canonicalJson, STAGE_B } from './production-green-stage-b-contract.mjs';
import { createAssumedRoleSessionEnvironment, createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from './production-credential-source-contract.mjs';

const ROLE = 'arn:aws:iam::368992683803:role/mscqr-production-release-deployer';
const PROFILE = 'mscqr-production-release-deployer';
const MAX_WRITER_SESSION_MS = 12 * 60 * 60 * 1000;
const digest = value => createHash('sha256').update(value).digest('hex');
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const assumptions = ['AssumeRole', 'AssumeRoleWithWebIdentity', 'AssumeRoleWithSAML'];
const parseIssuance = bytes => { try { return JSON.parse(bytes); } catch { throw new Error('Invalid CloudTrail issuance response'); } };
function timestamp(value, awsExpiration = false) {
  assert.equal(typeof value, 'string');
  const milliseconds = Date.parse(awsExpiration && !/(?:Z|GMT|UTC|[+-]\d\d:\d\d)$/.test(value) ? `${value} UTC` : value);
  assert.ok(Number.isFinite(milliseconds), 'Invalid AWS session timestamp'); return milliseconds;
}
export function assertBrokerWriterSession(session) {
  assert.deepEqual(Object.keys(session).sort(), ['accessKeyIdSha256', 'callerArn', 'callerUserId', 'eventId', 'expiresAt', 'issuedAt'].sort());
  assert.match(session.accessKeyIdSha256, /^[a-f0-9]{64}$/);
  assert.match(session.callerArn, /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[\w+=,.@-]{2,64}$/);
  assert.match(session.callerUserId, /^AROA[A-Z0-9]+:[\w+=,.@-]{2,64}$/);
  assert.equal(session.callerUserId.split(':')[1], session.callerArn.split('/').at(-1));
  assert.match(session.eventId, /^[a-f0-9-]{36}$/);
  const duration = timestamp(session.expiresAt) - timestamp(session.issuedAt);
  assert.ok(duration >= 900000 && duration <= 43200000, 'Unbounded role session');
  return session;
}
function assertIssuanceWindow(window) {
  assert.ok(window && typeof window === 'object', 'Authenticated issuance interval required');
  const start = timestamp(window.startTime), end = timestamp(window.endTime);
  assert.ok(start < end && end - start <= MAX_WRITER_SESSION_MS, 'Invalid authenticated issuance interval');
  return { startTime: new Date(start).toISOString(), endTime: new Date(end).toISOString(), start, end };
}
export function authenticateBrokerSessionIssuance(events, identity, window) {
  const interval = assertIssuanceWindow(window);
  const matches = events.filter(event => digest(event.responseElements?.credentials?.accessKeyId || '') === identity.accessKeyIdSha256);
  assert.equal(matches.length, 1, 'Missing/ambiguous independently authenticated STS issuance');
  const event = matches[0];
  const issuedAt = timestamp(event.eventTime);
  assert.ok(issuedAt >= interval.start && issuedAt <= interval.end, 'STS issuance is outside the authenticated interval');
  assert.equal(event.eventSource, 'sts.amazonaws.com'); assert.ok(assumptions.includes(event.eventName));
  assert.equal(event.awsRegion, STAGE_B.region); assert.equal(event.recipientAccountId, STAGE_B.account);
  assert.equal(event.errorCode, undefined); assert.equal(event.errorMessage, undefined);
  assert.equal(event.requestParameters.roleArn, ROLE);
  equal(event.responseElements.assumedRoleUser, { arn: identity.callerArn, assumedRoleId: identity.callerUserId });
  assert.equal(event.requestParameters.roleSessionName, identity.callerArn.split('/').at(-1));
  return assertBrokerWriterSession({ ...identity, eventId: event.eventID, issuedAt: new Date(timestamp(event.eventTime)).toISOString(),
    expiresAt: new Date(timestamp(event.responseElements.credentials.expiration, true)).toISOString() });
}

// Only AWS-returned events enter this function in production. Reduce them before
// persisting anything: CloudTrail can contain session tokens; never log raw events.
export function readBrokerSessionIssuance(run, identity, window) {
  const interval = assertIssuanceWindow(window);
  const events = new Map();
  for (const eventName of assumptions) {
    let token; const seen = new Set();
    for (let page = 0; page < 100; page++) {
      const result = parseIssuance(run(['cloudtrail', 'lookup-events', '--lookup-attributes', `AttributeKey=EventName,AttributeValue=${eventName}`,
        '--start-time', interval.startTime, '--end-time', interval.endTime, '--max-results', '50', '--no-paginate',
        ...(token ? ['--next-token', token] : []), '--region', STAGE_B.region, '--output', 'json', '--no-cli-pager']));
      assert.ok(Array.isArray(result.Events));
      for (const item of result.Events) {
        const event = parseIssuance(item.CloudTrailEvent);
        if (digest(event.responseElements?.credentials?.accessKeyId || '') !== identity.accessKeyIdSha256) continue;
        assert.equal(item.EventId, event.eventID);
        if (events.has(event.eventID)) assert.ok(canonicalJson(events.get(event.eventID)) === canonicalJson(event), 'Conflicting CloudTrail issuance event');
        events.set(event.eventID, event);
      }
      token = result.NextToken;
      if (!token) break;
      assert.equal(typeof token, 'string'); assert.ok(!seen.has(token), 'Repeated CloudTrail cursor'); seen.add(token);
      assert.ok(page < 99, 'CloudTrail issuance search incomplete');
    }
  }
  return authenticateBrokerSessionIssuance([...events.values()], identity, interval);
}
function writerSessionIssuanceWindow(expiration) {
  const end = timestamp(expiration, true);
  return { startTime: new Date(end - MAX_WRITER_SESSION_MS).toISOString(), endTime: new Date(end).toISOString() };
}
export async function readBrokerRecoveryAwsClock(fetcher = fetch) {
  // STS Query API uses POST; a bare HEAD is not a supported clock probe and
  // the regional endpoint may redirect it outside the service authority.
  // Its TLS-authenticated, unsigned GetCallerIdentity rejection still carries
  // an AWS Date, without credentials or a mutating operation.
  const response = await fetcher('https://sts.eu-west-2.amazonaws.com/', { method: 'POST', redirect: 'error', cache: 'no-store',
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'Action=GetCallerIdentity&Version=2011-06-15', signal: AbortSignal.timeout(10000) });
  assert.equal(response.status, 403, 'Unexpected regional STS clock-probe response');
  assert.equal(response.url, 'https://sts.eu-west-2.amazonaws.com/');
  assert.equal(response.redirected, false, 'Redirected STS response is not clock authority');
  assert.match(await response.text(), /<ErrorResponse xmlns="https:\/\/sts\.amazonaws\.com\/doc\/2011-06-15\/">[\s\S]*<Code>MissingAuthenticationToken<\/Code>[\s\S]*<\/ErrorResponse>/,
    'Response is not the expected STS Query API authentication rejection');
  const date = response.headers.get('date'); assert.ok(date, 'Missing authenticated AWS clock');
  assert.equal(response.headers.get('age'), null, 'Cached clock is not authority');
  const milliseconds = timestamp(date);
  assert.equal(new Date(milliseconds).toUTCString(), date, 'Malformed AWS HTTP Date');
  return new Date(milliseconds).toISOString();
}
export async function proveBrokerWriterUnusable(owner, { readIssuance, readClock }) {
  assert.ok(owner.writerSession, 'Legacy/unbound ownership cannot be recovered automatically');
  assertBrokerWriterSession(owner.writerSession);
  const authenticated = await readIssuance(owner.writerSession);
  equal(authenticated, owner.writerSession); // Never trust a claimed shorter expiry.
  const observedAt = await readClock();
  assert.ok(timestamp(observedAt) > timestamp(authenticated.expiresAt), 'Previous writer credentials remain usable');
  return { mechanism: 'AWS_STS_AUTHENTICATED_EXPIRY', ownerSha256: digest(canonicalJson(owner)), session: authenticated, observedAt,
    previousWriterCannotContinue: true, processTerminationProven: false };
}
export function authenticateBrokerAliasCasEvent(events, { preparation: p, authorization, authorizedAt, alias }) {
  const lower = value => {
    assert.ok(value && typeof value === 'object'); const pairs = Object.entries(value).map(([k, v]) => [k[0].toLowerCase() + k.slice(1), v]);
    assert.equal(new Set(pairs.map(([k]) => k)).size, pairs.length); return Object.fromEntries(pairs);
  };
  const request = { functionName: STAGE_B.brokerFunctionArn, name: p.alias.Name, functionVersion: p.target.version, revisionId: p.alias.RevisionId,
    description: p.alias.Description, routingConfig: { additionalVersionWeights: p.alias.RoutingConfig.AdditionalVersionWeights } };
  const candidates = events.filter(e => e.eventSource === 'lambda.amazonaws.com' && e.eventName === 'UpdateAlias20150331'
    && e.awsRegion === STAGE_B.region && e.recipientAccountId === STAGE_B.account && !e.errorCode && !e.errorMessage
    && timestamp(e.eventTime) >= Math.floor(timestamp(authorizedAt) / 1000) * 1000
    && timestamp(e.eventTime) < timestamp(authorization.expiresAt)
    && typeof e.userAgent === 'string' && e.userAgent.split(/\s+/).filter(v => v.startsWith('exec-env/')).join(' ') === `exec-env/mscqr-broker-cutover-${brokerDigest(authorization)}`
    && e.userIdentity?.sessionContext?.sessionIssuer?.arn === ROLE
    && e.requestParameters && canonicalJson(lower(e.requestParameters)) === canonicalJson(request));
  assert.equal(candidates.length, 1, 'Missing/ambiguous independently authenticated alias CAS execution');
  const event = candidates[0], response = lower(event.responseElements);
  assert.deepEqual(Object.keys(response).sort(), ['aliasArn', 'description', 'functionVersion', 'name', 'revisionId', 'routingConfig']);
  const routing = lower(response.routingConfig); assert.deepEqual(Object.keys(routing), ['additionalVersionWeights']);
  equal(brokerAliasIdentity({ AliasArn: response.aliasArn, Name: response.name, FunctionVersion: response.functionVersion,
    RevisionId: response.revisionId, Description: response.description, RoutingConfig: { AdditionalVersionWeights: routing.additionalVersionWeights } }), alias);
  assert.match(event.eventID || '', /^[a-f0-9-]{36}$/);
  return { mechanism: 'AWS_CLOUDTRAIL_NATIVE_ALIAS_CAS', eventId: event.eventID, eventTime: event.eventTime,
    authorizationSha256: brokerDigest(authorization), preparationSha256: brokerDigest(p), aliasSha256: brokerDigest(alias) };
}

export function createBrokerWriterSessionBoundary({ env = process.env, exec = execFileSync, independentRun } = {}) {
  const administrator = independentRun || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: 'mscqr-ops-admin', env, exec });
  const authenticateReader = () => {
    const caller = JSON.parse(administrator(['sts', 'get-caller-identity', '--output', 'json', '--no-cli-pager']));
    assert.equal(caller.Account, STAGE_B.account);
    assert.ok(caller.Arn === 'arn:aws:iam::368992683803:user/mscqr-ops-admin' || /^arn:aws:sts::368992683803:assumed-role\/mscqr-ops-admin\/[^/]+$/.test(caller.Arn), 'Independent CloudTrail reader required');
  };
  return {
    pin() {
      authenticateReader();
      let credentials;
      try {
        credentials = JSON.parse(exec(exec === execFileSync ? productionAwsExecutable() : 'aws', ['configure', 'export-credentials', '--profile', PROFILE, '--format', 'process'],
          { env: createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: PROFILE, env }), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
      } catch { throw new Error('Cannot resolve one bounded broker writer session'); }
      assert.ok(/^ASIA[A-Z0-9]{16}$/.test(credentials.AccessKeyId || ''), 'Temporary writer credential required'); assert.ok(credentials.SessionToken);
      const frozenEnvironment = createAssumedRoleSessionEnvironment({ credentials, env });
      const frozenRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION, env: frozenEnvironment, exec: (command, args, options) => exec(command, args, { ...options, env: { ...options.env, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard' } }) });
      const run = args => {
        assert.ok(args[0] !== 'configure' && (args[0] !== 'sts' || args[1] === 'get-caller-identity'), 'Pinned writer cannot acquire another session');
        assert.ok(!args.some(arg => /^(?:--profile|--endpoint-url|--no-verify-ssl)(?:=|$)/.test(arg)), 'Pinned credential authority cannot be redirected');
        return frozenRun(args);
      };
      const caller = JSON.parse(run(['sts', 'get-caller-identity', '--output', 'json', '--no-cli-pager']));
      assert.equal(caller.Account, STAGE_B.account);
      const window = writerSessionIssuanceWindow(credentials.Expiration);
      const session = readBrokerSessionIssuance(administrator, { accessKeyIdSha256: digest(credentials.AccessKeyId), callerArn: caller.Arn, callerUserId: caller.UserId }, window);
      assert.equal(session.expiresAt, window.endTime, 'Pinned credential expiration differs from authenticated STS issuance');
      // No profile/provider is left in the writer's environment. Expiry cannot
      // trigger CLI/provider refresh; a later invocation cannot replay its journal.
      return { session, run, environment: frozenEnvironment };
    },
    proveAliasCas(value) {
      authenticateReader(); const events = new Map(), seen = new Set(); let token;
      for (let page = 0; page < 100; page++) {
        const result = parseIssuance(administrator(['cloudtrail', 'lookup-events', '--lookup-attributes', 'AttributeKey=EventName,AttributeValue=UpdateAlias20150331',
          '--start-time', new Date(Math.floor(Date.parse(value.authorizedAt) / 1000) * 1000).toISOString(), '--end-time', value.authorization.expiresAt, '--max-results', '50', '--no-paginate',
          ...(token ? ['--next-token', token] : []), '--region', STAGE_B.region, '--output', 'json', '--no-cli-pager']));
        assert.ok(Array.isArray(result.Events));
        for (const item of result.Events) { const event = parseIssuance(item.CloudTrailEvent); assert.equal(item.EventId, event.eventID);
          if (events.has(event.eventID)) equal(events.get(event.eventID), event); events.set(event.eventID, event); }
        token = result.NextToken; if (!token) return authenticateBrokerAliasCasEvent([...events.values()], value);
        assert.ok(typeof token === 'string' && !seen.has(token)); seen.add(token);
      }
      throw Error('Incomplete alias CAS CloudTrail census');
    },
    prove: owner => { authenticateReader(); return proveBrokerWriterUnusable(owner, { readIssuance: session => readBrokerSessionIssuance(administrator,
      { accessKeyIdSha256: session.accessKeyIdSha256, callerArn: session.callerArn, callerUserId: session.callerUserId },
      { startTime: session.issuedAt, endTime: session.expiresAt }), readClock: readBrokerRecoveryAwsClock }); },
  };
}
