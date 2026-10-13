import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import yaml from 'js-yaml';

const action = yaml.load(fs.readFileSync('.github/actions/converge-stage-b-prerequisites/action.yml', 'utf8'));
const train = yaml.load(fs.readFileSync('.github/workflows/release-train.yml', 'utf8'));

test('OIDC window renews before another coordinator call and rejects invalid timestamps', () => {
  const step = action.runs.steps.find(value => value.id === 'converge');
  const script = step.run.match(/session_status="\$\(node -e '([^']+)'\)"/)?.[1];
  assert.ok(script, 'Missing actual hosted session guard');
  const now = Date.now();
  const expiry = offset => new Date(now + offset).toISOString();
  const check = value => spawnSync(process.execPath, ['-e', script], {encoding:'utf8',
    env:{...process.env, AWS_CREDENTIAL_EXPIRATION:value}});
  assert.equal(check(expiry(31 * 60 * 1000)).stdout, 'READY');
  assert.equal(check(expiry(29 * 60 * 1000)).stdout, 'RENEW_SESSION');
  assert.equal(check(expiry(-1)).stdout, 'RENEW_SESSION');
  const invalid = check('not-a-timestamp');
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /Invalid AWS session timestamp/);
});

test('hosted composite hands off an interrupted approval poll to fresh OIDC without another coordinator call', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-release-session-test-'));
  try {
    const count = path.join(dir, 'window-count');
    const calls = path.join(dir, 'coordinator-calls');
    fs.writeFileSync(count, '0');
    fs.writeFileSync(path.join(dir, 'node'), `#!/bin/sh
case "$1" in
  scripts/aws/run-production-release-coordinator.mjs)
    echo call >> "$MOCK_COORDINATOR_CALLS"
    if [ "$MOCK_MODE" = ROLL ]; then
      echo '{"status":"WAITING_FOR_APPROVAL","phase":"registration","runUrl":"https://github.com/T-ej2003/genuine-scan-main/actions/runs/123"}'
    else
      echo '{"status":"PREREQUISITES_CONVERGED"}'
    fi ;;
  -e)
    case "$2" in
      *AWS_CREDENTIAL_EXPIRATION*)
        n=$(cat "$MOCK_WINDOW_COUNT"); n=$((n + 1)); printf '%s' "$n" > "$MOCK_WINDOW_COUNT"
        if [ "$MOCK_MODE" = SHORT ] || { [ "$MOCK_MODE" = ROLL ] && [ "$n" -gt 1 ]; }; then echo RENEW_SESSION; else echo READY; fi ;;
      *) shift; exec "$REAL_NODE" -e "$@" ;;
    esac ;;
  *) exit 2 ;;
esac
`, {mode:0o700});
    fs.writeFileSync(path.join(dir, 'sleep'), '#!/bin/sh\nexit 0\n', {mode:0o700});
    const step = action.runs.steps.find(value => value.id === 'converge');
    const run = mode => {
      const output = path.join(dir, `output-${mode}`);
      const result = spawnSync('bash', ['-c', step.run], {encoding:'utf8', env:{...process.env,
        PATH:`${dir}:${process.env.PATH}`, REAL_NODE:process.execPath, MOCK_MODE:mode,
        MOCK_WINDOW_COUNT:count, MOCK_COORDINATOR_CALLS:calls, GITHUB_OUTPUT:output}});
      assert.equal(result.status, 0, result.stderr);
      return fs.readFileSync(output, 'utf8').trim();
    };
    assert.equal(run('ROLL'), 'status=WAITING_FOR_APPROVAL');
    assert.equal(fs.readFileSync(calls, 'utf8').trim().split('\n').length, 1);
    assert.equal(run('COMPLETE'), 'status=PREREQUISITES_CONVERGED');
    assert.equal(fs.readFileSync(calls, 'utf8').trim().split('\n').length, 2);
    const short = spawnSync('bash', ['-c', step.run], {encoding:'utf8', env:{...process.env,
      PATH:`${dir}:${process.env.PATH}`, REAL_NODE:process.execPath, MOCK_MODE:'SHORT',
      MOCK_WINDOW_COUNT:count, MOCK_COORDINATOR_CALLS:calls, GITHUB_OUTPUT:path.join(dir, 'output-SHORT')}});
    assert.notEqual(short.status, 0);
    assert.match(short.stdout, /Fresh AWS session is too short/);
    assert.equal(fs.readFileSync(calls, 'utf8').trim().split('\n').length, 2);
    const steps = train.jobs.orchestrate.steps;
    for (let n = 3; n <= 7; n++) {
      const continuation = steps.find(value => value.id === `converge_${n}`);
      assert.match(continuation.if, /WAITING_FOR_APPROVAL/);
    }
    assert.ok(action.runs.steps.findIndex(value => value.id === 'credentials') < action.runs.steps.findIndex(value => value.id === 'converge'));
  } finally { fs.rmSync(dir, {recursive:true, force:true}); }
});
