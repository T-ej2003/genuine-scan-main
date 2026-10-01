import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { manifest } from "./victoria-recovery-sql.mjs";

export const RECOVERY_DB_ROLE = "mscqr_prod_victoria_recovery";
export const RECOVERY_OWNER_ROLE = "mscqr_prod_victoria_recovery_owner";
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
const ident = (value) => {
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(value)) throw new Error(`Unsafe identifier ${value}`);
  return `"${value}"`;
};
const context = `(current_user=${quote(RECOVERY_OWNER_ROLE)} AND session_user=${quote(RECOVERY_DB_ROLE)} AND current_setting('app.victoria_recovery_operation',true)='VICTORIA_FAILED_ONBOARDING_RECOVERY_V1' AND current_setting('app.victoria_recovery_target_email',true)='victoria@mscqr.com')`;
const scopeFor = (table) => {
  if (table === "User") return `lower(btrim(email))='victoria@mscqr.com'`;
  if (table === "Invite") return `(lower(btrim(email))='victoria@mscqr.com' OR id=ANY(string_to_array(current_setting('app.victoria_recovery_invite_ids',true),',')) OR "createdByUserId"=current_setting('app.victoria_recovery_user_id',true) OR "acceptedByUserId"=current_setting('app.victoria_recovery_user_id',true))`;
  if (["AuditLog", "AuditLogOutbox"].includes(table) || manifest.liveRelations.some((relation) => relation.table === table && relation.classification === "IMMUTABLE_AUDIT")) return "true";
  const fields = [...new Set(manifest.liveRelations.filter((relation) => relation.table === table && relation.target === "User.id").map((relation) => relation.column))];
  if (table === "InviteActivationChallenge") return `("userId"=current_setting('app.victoria_recovery_user_id',true) OR "inviteId"=ANY(string_to_array(current_setting('app.victoria_recovery_invite_ids',true),',')))`;
  if (!fields.length) throw new Error(`No fixed row scope for ${table}`);
  return `(${fields.map((field) => `${ident(field)}=current_setting('app.victoria_recovery_user_id',true)`).join(" OR ")})`;
};

export function renderVictoriaRecoveryInstallationSql() {
  const tables = new Set(manifest.liveRelations.map(({ table }) => table));
  tables.add("User"); tables.add("Invite"); tables.add("AuditLog"); tables.add("AuditLogOutbox");
  const grants = new Map();
  const addColumns = (table, columns) => {
    const set = grants.get(table) || new Set();
    for (const column of columns) set.add(column);
    grants.set(table, set);
  };
  for (const relation of manifest.liveRelations) addColumns(relation.table, [relation.column, "id"]);
  addColumns("User", ["id", "email", "status", "role", "isActive", "lastLoginAt", "emailVerifiedAt", "disabledAt", "deletedAt"]);
  addColumns("Invite", ["id", "email", "role", "usedAt", "expiresAt", "createdByUserId", "acceptedByUserId"]);
  addColumns("PasswordReset", ["userId", "usedAt", "expiresAt"]);
  addColumns("EmailVerificationToken", ["userId", "usedAt", "expiresAt"]);
  addColumns("RefreshToken", ["userId", "revokedAt", "expiresAt", "sessionCapabilityRevokedAt", "sessionCapabilityExpiresAt"]);
  addColumns("AdminMfaCredential", ["userId"]);
  addColumns("AdminWebAuthnCredential", ["userId"]);
  addColumns("UserMfaFactor", ["userId"]);
  addColumns("UserBackupCode", ["userId"]);
  addColumns("InviteActivationChallenge", ["id", "userId", "inviteId"]);
  addColumns("AuditLog", ["id", "userId", "action", "entityId", "details"]);
  addColumns("AuditLogOutbox", ["id", "payload", "initiatingUserId"]);
  const grantSql = [...grants.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([table, columns]) => `GRANT SELECT (${[...columns].sort().map(ident).join(",")}) ON public.${ident(table)} TO ${ident(RECOVERY_OWNER_ROLE)};`).join("\n");
  const policies = [];
  for (const table of [...tables].sort()) {
    const name = `victoria_recovery_${table.toLowerCase()}_select`;
    policies.push(`CREATE POLICY ${ident(name)} ON public.${ident(table)} FOR SELECT TO ${ident(RECOVERY_OWNER_ROLE)} USING (${context} AND ${scopeFor(table)});`);
  }
  for (const table of ["User", "Invite", "InviteActivationChallenge", "PasswordReset", "EmailVerificationToken"]) {
    const scope = table === "User" ? `id=current_setting('app.victoria_recovery_user_id',true) AND lower(btrim(email))='victoria@mscqr.com'`
      : table === "Invite" ? `id=ANY(string_to_array(current_setting('app.victoria_recovery_invite_ids',true),',')) AND lower(btrim(email))='victoria@mscqr.com'`
        : table === "InviteActivationChallenge" ? `"userId"=current_setting('app.victoria_recovery_user_id',true) AND "inviteId"=ANY(string_to_array(current_setting('app.victoria_recovery_invite_ids',true),','))`
          : `"userId"=current_setting('app.victoria_recovery_user_id',true)`;
    const name = `victoria_recovery_${table.toLowerCase()}_delete`;
    policies.push(`CREATE POLICY ${ident(name)} ON public.${ident(table)} FOR DELETE TO ${ident(RECOVERY_OWNER_ROLE)} USING (${context} AND ${scope});`);
  }
  const routine = fs.readFileSync(new URL("../../backend/src/rls-waves/session-c/c05/victoriaRecovery.sql", import.meta.url), "utf8")
    .replaceAll("{{AUTH_OWNER}}", ident(RECOVERY_OWNER_ROLE));
  if (/\{\{[A-Z_]+\}\}/.test(routine)) throw new Error("Recovery installation SQL has unresolved placeholders.");
  return [
    `-- ACTIVE database only; generated from ${manifest.operation} dependency manifest.`,
    `BEGIN;`,
    `CREATE ROLE ${ident(RECOVERY_OWNER_ROLE)} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
    `CREATE ROLE ${ident(RECOVERY_DB_ROLE)} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`,
    `GRANT ${ident(RECOVERY_OWNER_ROLE)} TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;`,
    `GRANT USAGE,CREATE ON SCHEMA app_ops TO ${ident(RECOVERY_OWNER_ROLE)};`,
    `GRANT rds_iam TO ${ident(RECOVERY_DB_ROLE)};`,
    `GRANT CONNECT ON DATABASE mscqr_production TO ${ident(RECOVERY_DB_ROLE)};`,
    `GRANT USAGE ON SCHEMA app_ops TO ${ident(RECOVERY_DB_ROLE)};`,
    grantSql,
    `GRANT DELETE ON public."User",public."Invite",public."InviteActivationChallenge",public."PasswordReset",public."EmailVerificationToken" TO ${ident(RECOVERY_OWNER_ROLE)};`,
    policies.join("\n"),
    routine,
    `REVOKE CREATE ON SCHEMA app_ops FROM ${ident(RECOVERY_OWNER_ROLE)};`,
    `REVOKE ${ident(RECOVERY_OWNER_ROLE)} FROM CURRENT_USER;`,
    `COMMIT;`,
  ].join("\n\n") + "\n";
}

export function writeVictoriaRecoveryInstallationSql(output) {
  if (typeof output !== "string" || !path.isAbsolute(output)) throw new Error("An absolute private output path is required.");
  const sql = renderVictoriaRecoveryInstallationSql();
  fs.writeFileSync(output, sql, { mode: 0o600, flag: "wx" });
  return Object.freeze({ output, sha256: crypto.createHash("sha256").update(sql).digest("hex") });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const index = process.argv.indexOf("--output");
  try {
    if (process.argv.length !== 4 || index !== 2) throw new Error("INSTALLATION_ARGUMENTS_INVALID");
    process.stdout.write(`${JSON.stringify(writeVictoriaRecoveryInstallationSql(process.argv[3]))}\n`);
  } catch (error) {
    process.stderr.write(`${/^[A-Z0-9_]+$/.test(error.message) ? error.message : "INSTALLATION_SQL_WRITE_FAILED"}\n`);
    process.exitCode = 1;
  }
}
