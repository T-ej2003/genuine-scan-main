import fs from "node:fs";
export const ROTATION_INVENTORY_TABLES = Object.freeze(["RefreshToken", "User", "CustomerAuthSession", "CustomerVerificationSession", "Invite", "PasswordReset", "EmailVerificationToken", "QRCode", "CompliancePackJob"]);
export const rotationInventoryPolicyName = (table) => `rotation_inventory_${table.toLowerCase()}`;
const identifier = (value) => {
  if (!/^[a-z][a-z0-9_]*$/.test(value || "")) throw new Error("Invalid inventory role identity");
  return `"${value}"`;
};
export function rotationInventoryFunctionSql({ owner, app }) {
  identifier(owner); identifier(app);
  return fs.readFileSync(new URL("../../../backend/src/rls-waves/session-a/productionRotationInventory.sql", import.meta.url), "utf8")
    .replaceAll("{{APP_ROLE_LITERAL}}", `'${app}'`).replaceAll("{{APP_ROLE}}", identifier(app));
}
export function rotationInventoryPolicySql({ owner, app }) {
  identifier(owner); identifier(app);
  return ROTATION_INVENTORY_TABLES.map((table) => `CREATE POLICY "${rotationInventoryPolicyName(table)}" ON public."${table}" FOR SELECT TO ${identifier(owner)} USING (current_user='${owner}' AND session_user='${app}' AND current_setting('transaction_read_only')='on' AND current_setting('app.rotation_inventory_operation',true)='rotation-inventory-v1' AND COALESCE(current_setting('app.user_id',true),'')='' AND COALESCE(current_setting('app.role',true),'')='' AND COALESCE(current_setting('app.licensee_id',true),'')='' AND COALESCE(current_setting('app.auth_session_id',true),'')='' AND COALESCE(current_setting('app.context_installed',true),'')=''); COMMENT ON POLICY "${rotationInventoryPolicyName(table)}" ON public."${table}" IS 'Fixed aggregate-only read-only inventory boundary';`).join("\n");
}
