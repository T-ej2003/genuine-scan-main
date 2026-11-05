import test from 'node:test';
import assert from 'node:assert/strict';
import { runVictoriaDiagnostic, validateVictoriaDiagnosticResult } from '../security/victoria-diagnostic-result.mjs';

const row = () => ({ status: 'ACCOUNT_PRESENT', account_active: true, account_role: 'SUPER_ADMIN', mfa_enabled: true, totp_enabled: true, webauthn_present: null, backup_codes_present: null, c04_procedure_present: true, c04_execution_grants: ['mscqr_prod_breakglass_test'] });

test('fixed projection accepts and freezes only the reviewed fields', () => {
  const input = row();
  const output = validateVictoriaDiagnosticResult(input);
  input.c04_execution_grants.push('later');
  assert.deepEqual(output.c04_execution_grants, ['mscqr_prod_breakglass_test']);
  assert(Object.isFrozen(output));
  for (const mutation of [{ secret: 'never-return' }, { account_role: 'secret-value' }, { totp_enabled: false }, { c04_execution_grants: ['bad role'] }]) {
    assert.throws(() => validateVictoriaDiagnosticResult({ ...row(), ...mutation }), /Invalid diagnostic result/);
  }
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
