import { createHash } from 'node:crypto';

const fields = ['status', 'account_active', 'account_role', 'mfa_enabled', 'totp_enabled', 'webauthn_present', 'backup_codes_present', 'c04_procedure_present', 'c04_execution_grants'];
const statuses = new Set(['ACCOUNT_PRESENT', 'VISIBILITY_UNVERIFIED', 'EXECUTION_UNAUTHORIZED', 'DIAGNOSTIC_ERROR']);
const roles = new Set(['SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN', 'LICENSEE_ADMIN', 'ORG_ADMIN', 'MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER']);

export function validateVictoriaDiagnosticResult(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Invalid diagnostic result');
  const keys = Reflect.ownKeys(row);
  if (keys.some((key) => typeof key !== 'string') || keys.sort().join('|') !== [...fields].sort().join('|')) throw new Error('Invalid diagnostic result');
  const descriptors = Object.getOwnPropertyDescriptors(row);
  if (fields.some((key) => !Object.hasOwn(descriptors[key], 'value'))) throw new Error('Invalid diagnostic result');
  row = Object.fromEntries(fields.map((key) => [key, descriptors[key].value]));
  if (!statuses.has(row.status)) throw new Error('Invalid diagnostic result');
  const empty = fields.slice(1).every((key) => row[key] === null);
  if (row.status !== 'ACCOUNT_PRESENT') {
    if (!empty) throw new Error('Invalid diagnostic result');
  } else {
    if (typeof row.account_active !== 'boolean' || !roles.has(row.account_role)) throw new Error('Invalid diagnostic result');
    if (!['mfa_enabled', 'totp_enabled', 'webauthn_present', 'backup_codes_present'].every((key) => row[key] === null || row[key] === true)) throw new Error('Invalid diagnostic result');
    if ((row.totp_enabled === true || row.webauthn_present === true) !== (row.mfa_enabled === true)) throw new Error('Invalid diagnostic result');
    if (row.c04_procedure_present !== true && row.c04_procedure_present !== false) throw new Error('Invalid diagnostic result');
    if (row.c04_procedure_present === false) {
      if (row.c04_execution_grants !== null) throw new Error('Invalid diagnostic result');
    } else {
      if (!Array.isArray(row.c04_execution_grants)) throw new Error('Invalid diagnostic result');
      const grants = Object.getOwnPropertyDescriptors(row.c04_execution_grants);
      const length = grants.length?.value;
      if (!Number.isSafeInteger(length) || length > 100 || Reflect.ownKeys(grants).length !== length + 1) throw new Error('Invalid diagnostic result');
      row.c04_execution_grants = Array.from({ length }, (_, index) => {
        const descriptor = grants[index];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string' || !/^[a-zA-Z0-9_-]{1,63}$/.test(descriptor.value)) throw new Error('Invalid diagnostic result');
        return descriptor.value;
      });
    }
  }
  return Object.freeze({ ...row, c04_execution_grants: Array.isArray(row.c04_execution_grants) ? Object.freeze([...row.c04_execution_grants]) : null });
}

// This digest binds a sanitized projection; it is not an audit receipt or authorization.
export function victoriaDiagnosticResultSha256(row) {
  const validated = validateVictoriaDiagnosticResult(row);
  return createHash('sha256').update(JSON.stringify(Object.fromEntries(fields.map((key) => [key, validated[key]])))).digest('hex');
}

// Authentication and durable audit integration must be supplied by a reviewed execution contract.
export async function runVictoriaDiagnostic() {
  throw new Error('Victoria diagnostic execution is disabled');
}
