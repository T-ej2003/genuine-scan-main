const fields = ['status', 'account_active', 'account_role', 'mfa_enabled', 'totp_enabled', 'webauthn_present', 'backup_codes_present', 'c04_procedure_present', 'c04_execution_grants'];
const statuses = new Set(['ACCOUNT_PRESENT', 'VISIBILITY_UNVERIFIED', 'EXECUTION_UNAUTHORIZED', 'DIAGNOSTIC_ERROR']);
const roles = new Set(['SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN', 'LICENSEE_ADMIN', 'ORG_ADMIN', 'MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER']);

export function validateVictoriaDiagnosticResult(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join('|') !== [...fields].sort().join('|') || !statuses.has(row.status)) throw new Error('Invalid diagnostic result');
  const empty = fields.slice(1).every((key) => row[key] === null);
  if (row.status !== 'ACCOUNT_PRESENT') {
    if (!empty) throw new Error('Invalid diagnostic result');
  } else {
    if (typeof row.account_active !== 'boolean' || !roles.has(row.account_role)) throw new Error('Invalid diagnostic result');
    if (!['mfa_enabled', 'totp_enabled', 'webauthn_present', 'backup_codes_present'].every((key) => row[key] === null || row[key] === true)) throw new Error('Invalid diagnostic result');
    if (row.c04_procedure_present !== true && row.c04_procedure_present !== false) throw new Error('Invalid diagnostic result');
    if (row.c04_procedure_present === false ? row.c04_execution_grants !== null : !Array.isArray(row.c04_execution_grants) || row.c04_execution_grants.length > 100 || row.c04_execution_grants.some((role) => typeof role !== 'string' || !/^[a-zA-Z0-9_-]{1,63}$/.test(role))) throw new Error('Invalid diagnostic result');
  }
  return Object.freeze({ ...row, c04_execution_grants: Array.isArray(row.c04_execution_grants) ? Object.freeze([...row.c04_execution_grants]) : null });
}

// Authentication and durable audit integration must be supplied by a reviewed execution contract.
export async function runVictoriaDiagnostic() {
  throw new Error('Victoria diagnostic execution is disabled');
}
