import test from 'node:test';
import assert from 'node:assert/strict';
import { runVictoriaDiagnostic, validateVictoriaDiagnosticResult, victoriaDiagnosticResultSha256 } from '../security/victoria-diagnostic-result.mjs';

const row = () => ({ status: 'ACCOUNT_PRESENT', account_active: true, account_role: 'SUPER_ADMIN', mfa_enabled: true, totp_enabled: true, webauthn_present: null, backup_codes_present: null, c04_procedure_present: true, c04_execution_grants: ['mscqr_prod_breakglass_test'] });

test('fixed projection accepts and freezes only the reviewed fields', () => {
  const input = row();
  const output = validateVictoriaDiagnosticResult(input);
  input.c04_execution_grants.push('later');
  assert.deepEqual(output.c04_execution_grants, ['mscqr_prod_breakglass_test']);
  assert(Object.isFrozen(output));
  for (const mutation of [{ secret: 'never-return' }, { account_role: 'secret-value' }, { totp_enabled: false }, { mfa_enabled: null }, { c04_execution_grants: ['bad role'] }]) {
    assert.throws(() => validateVictoriaDiagnosticResult({ ...row(), ...mutation }), /Invalid diagnostic result/);
  }
});

test('accessor-backed values cannot change between validation and output', () => {
  let reads = 0;
  const input = row();
  Object.defineProperty(input, 'account_role', { enumerable: true, get() { reads++; return 'SUPER_ADMIN'; } });
  assert.throws(() => validateVictoriaDiagnosticResult(input), /Invalid diagnostic result/);
  assert.equal(reads, 0);
  const grants = ['safe'];
  Object.defineProperty(grants, '0', { enumerable: true, get() { reads++; return 'safe'; } });
  assert.throws(() => validateVictoriaDiagnosticResult({ ...row(), c04_execution_grants: grants }), /Invalid diagnostic result/);
  assert.equal(reads, 0);
});

test('unverified outcomes never carry account information', () => {
  assert.throws(() => validateVictoriaDiagnosticResult({ ...row(), status: 'VISIBILITY_UNVERIFIED' }), /Invalid diagnostic result/);
  const hidden = Object.fromEntries(Object.keys(row()).map((key) => [key, null]));
  hidden.status = 'VISIBILITY_UNVERIFIED';
  assert.deepEqual(validateVictoriaDiagnosticResult(hidden), hidden);
});

test('runner cannot be enabled through caller-supplied adapters or claims', async () => {
  let called = false;
  await assert.rejects(() => runVictoriaDiagnostic({ authenticated: true, audit: () => { called = true; } }), /execution is disabled/);
  assert.equal(called, false);
});

test('result digest binds only the complete validated projection in fixed key order', () => {
  const input = row();
  const reversed = Object.fromEntries(Object.entries(input).reverse());
  assert.equal(victoriaDiagnosticResultSha256(input), victoriaDiagnosticResultSha256(reversed));
  assert.notEqual(victoriaDiagnosticResultSha256(input), victoriaDiagnosticResultSha256({ ...input, account_active: false }));
  assert.throws(() => victoriaDiagnosticResultSha256({ ...input, secret: 'never-return' }), /Invalid diagnostic result/);
});

test('concurrent disabled executions never call identity or audit adapters', async () => {
  let called = 0;
  const forged = { identity: 'operator', approval: 'approved', audit: () => { called++; }, diagnostic: () => { called++; } };
  const outcomes = await Promise.allSettled(Array.from({ length: 20 }, () => runVictoriaDiagnostic(forged)));
  assert(outcomes.every((outcome) => outcome.status === 'rejected' && outcome.reason.message === 'Victoria diagnostic execution is disabled'));
  assert.equal(called, 0);
});
