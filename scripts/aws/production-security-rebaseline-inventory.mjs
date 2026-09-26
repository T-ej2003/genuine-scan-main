import assert from "node:assert/strict";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { appOnlyRequirementIdentity, createAppOnlyRequirements } from "./production-app-only-requirements.mjs";

export const SECURITY_REBASELINE_COLLECTOR_VERSION = "production-security-catalogue-v10";
export const SECURITY_REBASELINE_OPERATIONS = Object.freeze(["CREATE", "ALTER", "DROP_POLICY_OR_MANAGED_ROUTINE", "GRANT", "REVOKE",
  "ENABLE_RLS", "FORCE_RLS", "OWNERSHIP_CHANGE", "ROLE_CHANGE", "UNEXPECTED_OBJECT"]);
export const SECURITY_REBASELINE_COVERAGE = Object.freeze([
  ["extensions", "pg_extension", "securityExtensions", "extensions"],
  ["replication and user bindings", "pg_publication/pg_publication_rel/pg_publication_namespace/pg_subscription via app_rls.production_security_subscription_inventory (subconninfo represented only by a domain-separated digest)/pg_replication_slots/pg_db_role_setting/pg_seclabel/pg_operator/pg_cast/pg_foreign_data_wrapper/pg_foreign_server/pg_user_mapping/pg_foreign_table/pg_language/pg_largeobject_metadata (owner+ACL aggregate only; no OIDs or contents)", "securityBindings", "bindings"],
  ["routines", "pg_proc/pg_aggregate", "securityRoutines", "routines/routineGrants"],
  ["relations", "pg_class/pg_attribute/pg_constraint", "securityTables", "tables/tableGrants/columnGrants"],
  ["triggers", "pg_trigger", "securityTriggers", "triggers"], ["constraint enforcement", "pg_trigger/pg_constraint", "securityConstraintTriggers", "constraintTriggers"], ["rewrite rules", "pg_rewrite", "securityRules", "rules"],
  ["event triggers", "pg_event_trigger", "securityEventTriggers", "eventTriggers"], ["RLS policies", "pg_policy", "securityPolicies", "policies"],
  ["schemas", "pg_namespace", "securitySchemas", "schemas/schemaGrants"], ["roles and membership graph", "pg_roles/pg_auth_members", "securityRoles", "roles/unexpectedRoles/roleMemberships/roleMembers"],
  ["role metadata", "pg_shdescription/pg_db_role_setting", "roleMetadata", "roleMetadata"], ["database ACL", "pg_database", "databases", "databases/databaseGrants"],
  ["default ACL", "pg_default_acl", "defaults", "defaultPrivileges"], ["parameter ACL", "pg_parameter_acl", "parameterPrivileges", "parameterPrivileges"], ["types", "pg_type", "types", "types/typeGrants"],
  ["sequences", "pg_sequence/pg_class", "sequences", "sequences/sequenceGrants"], ["operator capabilities", "pg_roles/pg_auth_members", "operatorCapabilities", "operatorCapabilities/operatorMemberships/operatorInheritedCapabilities"],
].map(([surface, catalogue, rawCollection, normalizedCollections]) => Object.freeze({ surface, catalogue, rawCollection, normalizedCollections })));
const SHA40 = /^[a-f0-9]{40}$/, SHA256 = /^[a-f0-9]{64}$/;
const RAW_COLLECTIONS = Object.freeze(["routines", "securityRoutines", "securityExtensions", "securityBindings", "tables", "securityTables", "securityTriggers", "securityConstraintTriggers", "securityRules", "securityEventTriggers", "policies", "securityPolicies", "schemas", "securitySchemas", "roles", "securityRoles", "roleMetadata", "databases", "defaults", "parameterPrivileges", "types", "sequences", "operatorCapabilities"]);
const GRANTS = new Set(["routineGrants", "tableGrants", "columnGrants", "schemaGrants", "typeGrants", "sequenceGrants", "databaseGrants", "defaultPrivileges", "parameterPrivileges"]);
const FIELDS = Object.freeze({
  routines: ["kind","result","owner","security_definer","volatility","parallel","leakproof","strict","config","body","language","definition","aggregate_state_sha256"],
  extensions: ["version","schema","relocatable","owner"],
  bindings: ["kind","owner","definition"],
  tables: ["kind","rls","forced","owner","view_definition","view_security_options","partition_key","partition_bound","columns","constraints"], triggers: ["enabled","function","definition"],
  constraintTriggers: ["enabled","deferrable","initially_deferred"],
  rules: ["event","enabled","definition"], eventTriggers: ["owner","event","enabled","tags","function"], policies: ["permissive","command","roles","using","check"], schemas: ["owner"],
  roles: ["login","valid_until","connection_limit","superuser","inherit","create_role","create_database","replication","bypass_rls"],
  unexpectedRoles: ["login","valid_until","connection_limit","superuser","inherit","create_role","create_database","replication","bypass_rls","security_state_sha256"],
  databases: ["owner"],
  roleMetadata: ["comment_present","comment_sha256","settings","unsupported_settings"], types: ["kind","owner","category","not_null","base_type","collation","default_value","default_expression","enum_labels","constraints"],
  sequences: ["owner","data_type","start_value","increment_by","maximum","minimum","cache_size","cycle"],
  operatorCapabilities: ["login","valid_until","connection_limit","superuser","inherit","create_role","create_database","replication","bypass_rls","database_connect","database_create","database_temporary"],
  operatorMemberships: ["present"], operatorInheritedCapabilities: ["present"],
  routineGrants: ["present"], tableGrants: ["present"], columnGrants: ["present"], schemaGrants: ["present"], typeGrants: ["present"], sequenceGrants: ["present"],
  databaseGrants: ["present"], defaultPrivileges: ["present"], parameterPrivileges: ["present"], roleMemberships: ["present"], roleMembers: ["present"],
});
export const SECURITY_REBASELINE_NORMALIZED_COLLECTIONS = Object.freeze(Object.keys(FIELDS));
const MANAGED_SCHEMAS = new Set(["app_rls", "app_auth", "app_public", "app_ops"]);
const MANAGED_ROLE = /^(?:mscqr_prd_rls_phase2_[a-z0-9_]+|mscqr_prod_rls_canary_read|mscqr_prod_admin|mscqr_prod_subscription_observer)$/;
const APP_ONLY_ROLE = /^(?:mscqr_prd_rls_phase2_[a-z0-9_]+|mscqr_prod_rls_canary_read)$/;
const CANONICAL_HARNESS_ROLES = new Set(["mscqr_p2_test", "certification-administrator"]);
const CANONICAL_MEMBERSHIP_GRANTOR = "mscqr_p2_test", PRODUCTION_MEMBERSHIP_GRANTOR = "rdsadmin";
const CANONICAL_MEMBERSHIP_PARENT = /^mscqr_prd_rls_phase2_[a-z0-9_]+$/;
// PostgreSQL reserves pg_*; these exact RDS roles are provider-owned. Other
// rds_* names remain observable user roles rather than being hidden by prefix.
const SYSTEM_ROLE = /^(?:pg_[A-Za-z0-9_]+|rdsadmin|rds_superuser|rds_password|rds_iam|rds_replication|rds_ad|rds_directory_service_role|rds_reserved|rdstopmgr)$/;
const ROLE_NAME = /^[A-Za-z_][A-Za-z0-9_$-]{0,127}$/;
const SENSITIVE = /(?:postgres(?:ql)?:\/\/[^\s@]+@|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|DATABASE_URL\s*=)/i;
const exactKeys = (value, keys, label) => { assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`); assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} contains an unsupported field`); };
const sorted = (value) => Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)));
const rowIdentity = (collection, row) => collection === "routines" ? `${appOnlyRequirementIdentity(collection, row)}:${row.kind}`
  : collection === "policies" ? `${row.schema}.${row.table}.${row.name}`
  : collection === "triggers" ? `${row.schema}.${row.relation}.${row.name}`
  : collection === "constraintTriggers" ? canonicalJson([row.constraint_schema,row.constraint_relation,row.constraint_name,row.schema,row.relation,row.function,row.trigger_type])
  : collection === "types" || collection === "sequences" ? `${row.schema}.${row.name}`
    : collection === "databases" ? canonicalJson([row.database, row.role, row.grantor, row.privilege, row.grantable])
      : collection === "defaults" ? canonicalJson([row.owner, row.schema, row.object_type, row.role, row.grantor, row.privilege, row.grantable]) : row.name;
const grantIdentity = (owner, grant, column = null) => canonicalJson([owner, column, grant.role, grant.grantor, grant.privilege, grant.grantable]);
const membershipIdentity = (owner, value, direction) => canonicalJson([owner, direction, value.role ?? value.member, value.grantor, value.admin, value.inherit, value.set]);
function assertSecurityMetadata(value, location = "catalogue") {
  if (typeof value === "string") { assert.ok(Buffer.byteLength(value) <= 256 * 1024, `${location} contains oversized metadata`); assert.ok(!SENSITIVE.test(value), `${location} contains secret-shaped material`); return; }
  if (value === null || typeof value === "boolean" || typeof value === "number") return;
  if (Array.isArray(value)) { assert.ok(value.length <= 20000, `${location} is oversized`); value.forEach((entry, index) => assertSecurityMetadata(entry, `${location}[${index}]`)); return; }
  assert.ok(value && typeof value === "object", `${location} contains unsupported metadata`);
  for (const [key, entry] of Object.entries(value)) { assert.ok(!/^(?:password|password_hash|rolpassword|secret|credential|database_url|token)$/i.test(key), `${location} contains a forbidden field`); assertSecurityMetadata(entry, `${location}.${key}`); }
}

function canonicalizeDisposableHarness(catalogue) {
  const result = structuredClone(catalogue);
  const harness = result.securityRoles.find(({ name }) => name === CANONICAL_MEMBERSHIP_GRANTOR);
  const authenticateHarness = () => {
    assert.ok(harness, "Canonical membership grantor is not the source-owned disposable harness");
    for (const field of ["login","superuser","inherit","create_role","create_database","replication","bypass_rls"])
      assert.equal(harness[field], true, "Canonical disposable harness identity is not authenticated");
  };
  const normalize = (membership, parent, member) => {
    const expected = member === "mscqr_prod_admin" && CANONICAL_MEMBERSHIP_PARENT.test(parent)
      && membership.admin === false && membership.inherit === false && membership.set === true;
    if (!expected && membership.grantor === CANONICAL_MEMBERSHIP_GRANTOR)
      assert.fail("Disposable harness granted an unsupported canonical membership");
    if (!expected) return membership;
    assert.ok([CANONICAL_MEMBERSHIP_GRANTOR, PRODUCTION_MEMBERSHIP_GRANTOR].includes(membership.grantor),
      "Canonical managed membership has an unsupported grantor");
    if (membership.grantor === CANONICAL_MEMBERSHIP_GRANTOR) authenticateHarness();
    return { ...membership, grantor: PRODUCTION_MEMBERSHIP_GRANTOR };
  };
  for (const role of result.securityRoles) {
    role.memberships = role.memberships.map((membership) => normalize(membership, membership.role, role.name));
    role.members = role.members.map((membership) => normalize(membership, role.name, membership.member));
  }
  for (const operator of result.operatorCapabilities)
    operator.memberships = operator.memberships.map((membership) => normalize(membership, membership.role, operator.name));
  for (const extension of result.securityExtensions)
    if (extension.name === "plpgsql" && extension.schema === "pg_catalog" && extension.owner === CANONICAL_MEMBERSHIP_GRANTOR) {
      authenticateHarness(); extension.owner = PRODUCTION_MEMBERSHIP_GRANTOR;
    }
  for (const binding of result.securityBindings)
    if (binding.kind === "language" && binding.name === "plpgsql") {
      if (binding.owner === CANONICAL_MEMBERSHIP_GRANTOR) { authenticateHarness(); binding.owner = PRODUCTION_MEMBERSHIP_GRANTOR; }
      for (const grant of binding.definition.grants || []) if (grant.grantor === CANONICAL_MEMBERSHIP_GRANTOR) {
        authenticateHarness(); grant.grantor = PRODUCTION_MEMBERSHIP_GRANTOR;
      }
      for (const grant of binding.definition.grants || []) if (grant.role === CANONICAL_MEMBERSHIP_GRANTOR) {
        authenticateHarness(); grant.role = PRODUCTION_MEMBERSHIP_GRANTOR;
      }
    }
  return result;
}

export function normalizeSecurityRebaselineCatalogue(catalogue, { kind = "LIVE" } = {}) {
  exactKeys(catalogue, ["identity", ...RAW_COLLECTIONS], "Security catalogue"); assertSecurityMetadata(catalogue);
  exactKeys(catalogue.identity, ["role","session_role","database","server_version_num","read_only","default_read_only","rolsuper","rolinherit","rolcreaterole","rolcreatedb","rolreplication","rolbypassrls","memberships","write_privileges","schema_write","database_write"], "Security catalogue identity");
  for (const collection of RAW_COLLECTIONS) assert.ok(Array.isArray(catalogue[collection]), `${collection} must be an array`);
  const objects = new Map();
  const add = (collection, identity, fields) => { assert.ok(typeof identity === "string" && identity.length > 0 && identity.length <= 4096); const key = `${collection}\0${identity}`; assert.ok(!objects.has(key), `Duplicate ${collection} identity`); objects.set(key, { collection, identity, fields: sorted(fields) }); };
  // This exact role is the isolated PG18 test-container administrator, not a
  // production target role. It remains visible in live mode and is excluded
  // only from the source-owned canonical fixture.
  const isCanonicalHarnessRole = (name) => kind === "CANONICAL" && CANONICAL_HARNESS_ROLES.has(name);
  const roleNames = new Set(catalogue.securityRoles.map(({ name }) => name).filter((name) => !isCanonicalHarnessRole(name)));
  const addUnexpectedRole = (role) => { assert.match(role || "", ROLE_NAME, "Security catalogue role identity is malformed"); if (role !== "PUBLIC" && !MANAGED_ROLE.test(role) && !SYSTEM_ROLE.test(role) && !isCanonicalHarnessRole(role)) assert.ok(roleNames.has(role), "Security catalogue references an uncollected user role"); };
  const addGrants = (collection, owner, grants, columnKey = null) => { assert.ok(Array.isArray(grants)); for (const grant of grants) { exactKeys(grant, [...(columnKey ? [columnKey] : []), "role", "grantor", "privilege", "grantable"], `${collection} grant`); const identity = grantIdentity(owner, grant, columnKey ? grant[columnKey] : null); addUnexpectedRole(grant.role, `${collection}:${identity}`); addUnexpectedRole(grant.grantor, `${collection}-grantor:${identity}`); add(collection, identity, { present: true }); } };
  const assertOptions = (options, label) => { assert.ok(Array.isArray(options)); for (const option of options) { exactKeys(option, ["name","value_sha256"], `${label} option`); assert.match(option.name || "", /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/); assert.match(option.value_sha256 || "", SHA256); } assert.equal(new Set(options.map(({ name }) => name)).size, options.length, `${label} has duplicate options`); };
  const assertBinding = (row) => {
    const fields = ({ publication:["all_tables","insert","update","delete","truncate","via_root","generated_columns"], publication_relation:["publication","schema","relation","columns","row_filter"], publication_schema:["publication","schema"], subscription:["enabled","binary","streaming","two_phase","disable_on_error","password_required","run_as_owner","failover","slot_name","synchronous_commit","publications","origin","skip_lsn","connection_info_sha256"], replication_slot:["plugin","slot_type","database","temporary","two_phase","failover","synced"], database_setting:["settings"], security_label:["provider","label_sha256"], operator:["result","function","commutator","negator","merge","hash"], cast:["context","method","function"], foreign_server:["wrapper","type","version","options","grants"], foreign_data_wrapper:["handler","validator","options","grants"], language:["trusted","handler","inline","validator","grants"], user_mapping:["options_visible","options"], foreign_table:["server","options"], large_objects:["count","grants"] })[row.kind];
    assert.ok(fields, `Unsupported security binding kind ${row.kind}`); exactKeys(row.definition, fields, `${row.kind} definition`);
    if (["foreign_server","foreign_data_wrapper","foreign_table"].includes(row.kind)) assertOptions(row.definition.options, row.kind);
    if (row.kind === "database_setting") assertOptions(row.definition.settings, row.kind);
    if (row.kind === "security_label") assert.match(row.definition.label_sha256 || "", SHA256);
    if (row.kind === "subscription") assert.match(row.definition.connection_info_sha256 || "", SHA256, "Subscription connection identity must be represented only by its digest");
    if (row.kind === "user_mapping") { assert.equal(row.definition.options_visible, true, "User-mapping options are not visible to the restricted collector"); assertOptions(row.definition.options, row.kind); }
    if (row.kind === "large_objects") assert.ok(Number.isSafeInteger(row.definition.count) && row.definition.count > 0, "Large-object metadata count is invalid");
    for (const grant of row.definition.grants || []) { exactKeys(grant, ["role","grantor","privilege","grantable"], `${row.kind} grant`); addUnexpectedRole(grant.role); addUnexpectedRole(grant.grantor); }
  };
  for (const row of catalogue.securityExtensions) { exactKeys(row, ["name","version","schema","relocatable","owner"], "Extension"); const { name, ...fields } = row; addUnexpectedRole(row.owner); add("extensions", name, fields); }
  for (const row of catalogue.securityBindings) { exactKeys(row, ["kind","name","owner","definition"], "Security binding"); if (row.owner !== null) addUnexpectedRole(row.owner); assertBinding(row); const { name, ...fields } = row; add("bindings", `${row.kind}:${name}`, fields); }
  for (const row of catalogue.securityRoutines) { exactKeys(row, ["schema","name","arguments","kind","result","owner","security_definer","volatility","parallel","leakproof","strict","config","body","language","definition","aggregate_state_sha256","grants"], "Routine"); const identity = rowIdentity("routines", row), fields = structuredClone(row), grants = fields.grants; delete fields.schema; delete fields.name; delete fields.arguments; delete fields.grants; add("routines", identity, fields); addGrants("routineGrants", identity, grants); }
  for (const row of catalogue.securityTables) { exactKeys(row, ["schema","name","kind","rls","forced","owner","view_definition","view_security_options","partition_key","partition_bound","columns","constraints","grants","column_grants"], "Table"); const identity=`${row.schema}.${row.name}`, { grants, column_grants: columnGrants, ...fields } = row; delete fields.schema; delete fields.name; add("tables", identity, fields); addGrants("tableGrants", identity, grants); addGrants("columnGrants", identity, columnGrants, "column"); }
  for (const row of catalogue.securityTriggers) { exactKeys(row, ["schema","relation","name","enabled","function","definition"], "Trigger"); const identity=rowIdentity("triggers", row), { schema, relation, name, ...fields } = row; add("triggers", identity, fields); }
  for (const row of catalogue.securityConstraintTriggers) { exactKeys(row, ["constraint_schema","constraint_relation","constraint_name","schema","relation","enabled","function","trigger_type","deferrable","initially_deferred"], "Constraint trigger"); const identity=rowIdentity("constraintTriggers", row), fields={ enabled:row.enabled,deferrable:row.deferrable,initially_deferred:row.initially_deferred }; add("constraintTriggers", identity, fields); }
  for (const row of catalogue.securityRules) { exactKeys(row, ["schema","relation","name","event","enabled","definition"], "Rule"); const identity=`${row.schema}.${row.relation}.${row.name}`, { schema, relation, name, ...fields } = row; add("rules", identity, fields); }
  for (const row of catalogue.securityEventTriggers) { exactKeys(row, ["name","owner","event","enabled","tags","function"], "Event trigger"); const { name, ...fields } = row; addUnexpectedRole(row.owner); add("eventTriggers", name, fields); }
  for (const row of catalogue.securityPolicies) { exactKeys(row, ["schema","table","name","permissive","command","roles","using","check"], "Policy"); const identity = rowIdentity("policies", row), { schema, table, name, ...fields } = row; add("policies", identity, fields); }
  for (const row of catalogue.securitySchemas) { exactKeys(row, ["name","owner","grants"], "Schema"); const { name, grants, ...fields } = row; add("schemas", name, fields); addGrants("schemaGrants", name, grants); }
  const metadataByRole = new Map(catalogue.roleMetadata.map((row) => [row.name, row]));
  assert.deepEqual(catalogue.roles.map(({ name }) => name).sort(), catalogue.securityRoles.map(({ name }) => name).filter((name) => APP_ONLY_ROLE.test(name)).sort(), "Legacy app-only roles diverge from the security inventory");
  for (const row of catalogue.securityRoles) { exactKeys(row, ["name","login","valid_until","connection_limit","superuser","inherit","create_role","create_database","replication","bypass_rls","memberships","members"], "Security role"); const { name, memberships, members, ...fields } = row; const metadata = metadataByRole.get(name); assert.ok(metadata, `Role metadata missing for ${name}`); if (!isCanonicalHarnessRole(name)) { if (MANAGED_ROLE.test(name)) add("roles", name, fields); else if (!SYSTEM_ROLE.test(name)) add("unexpectedRoles", name, { ...fields, security_state_sha256: canonicalSha256(metadata) }); } for (const value of memberships) { exactKeys(value, ["role","grantor","admin","inherit","set"], "Role membership"); const identity = membershipIdentity(name, value, "member-of"); addUnexpectedRole(value.role); addUnexpectedRole(value.grantor); add("roleMemberships", identity, { present: true }); } for (const value of members) { exactKeys(value, ["member","grantor","admin","inherit","set"], "Role member"); const identity = membershipIdentity(name, value, "has-member"); addUnexpectedRole(value.member); addUnexpectedRole(value.grantor); add("roleMembers", identity, { present: true }); } }
  for (const row of catalogue.roleMetadata) { exactKeys(row, ["name","comment_present","comment_sha256","settings","unsupported_settings"], "Role metadata"); assert.match(row.comment_sha256 || "", SHA256); assert.ok(Array.isArray(row.settings)); for (const setting of row.settings) { exactKeys(setting, ["database","settings"], "Role setting"); assert.ok(Array.isArray(setting.settings) && setting.settings.every((value) => /^(?:statement_timeout|lock_timeout|idle_in_transaction_session_timeout|search_path|default_transaction_read_only|row_security)=/.test(value))); } if (MANAGED_ROLE.test(row.name)) { assert.equal(row.unsupported_settings, false, "Managed role has an unsupported setting"); const { name, ...fields } = row; add("roleMetadata", name, fields); } }
  assert.deepEqual(catalogue.roleMetadata.map(({ name }) => name).sort(), catalogue.securityRoles.map(({ name }) => name).sort(), "Security role metadata is incomplete");
  const databaseOwners = new Map(); for (const row of catalogue.databases) { exactKeys(row, ["database","owner","role","grantor","privilege","grantable"], "Database ACL"); const identity = rowIdentity("databases", row); addUnexpectedRole(row.role, `database:${identity}`); addUnexpectedRole(row.grantor, `database-grantor:${identity}`); if (databaseOwners.has(row.database)) assert.equal(databaseOwners.get(row.database), row.owner); else databaseOwners.set(row.database, row.owner); add("databaseGrants", identity, { present: true }); } for (const [database, owner] of databaseOwners) add("databases", database, { owner });
  for (const row of catalogue.defaults) { exactKeys(row, ["owner","schema","object_type","role","grantor","privilege","grantable"], "Default privilege"); const identity = rowIdentity("defaults", row); addUnexpectedRole(row.owner, `default-owner:${identity}`); addUnexpectedRole(row.role, `default:${identity}`); addUnexpectedRole(row.grantor, `default-grantor:${identity}`); add("defaultPrivileges", identity, { present: true }); }
  for (const row of catalogue.parameterPrivileges) { exactKeys(row, ["parameter","role","grantor","privilege","grantable"], "Parameter privilege"); const identity = canonicalJson([row.parameter,row.role,row.grantor,row.privilege,row.grantable]); addUnexpectedRole(row.role); addUnexpectedRole(row.grantor); add("parameterPrivileges", identity, { present: true }); }
  for (const collection of ["types", "sequences"]) for (const row of catalogue[collection]) { exactKeys(row, collection === "types" ? ["schema","name","kind","owner","category","not_null","base_type","collation","default_value","default_expression","enum_labels","constraints","grants"] : ["schema","name","owner","data_type","start_value","increment_by","maximum","minimum","cache_size","cycle","grants"], collection); const identity = rowIdentity(collection, row), { grants, schema, name, ...fields } = row; add(collection, identity, fields); addGrants(collection === "types" ? "typeGrants" : "sequenceGrants", identity, grants); }
  for (const row of catalogue.operatorCapabilities) { exactKeys(row, ["name","login","valid_until","connection_limit","superuser","inherit","create_role","create_database","replication","bypass_rls","database_connect","database_create","database_temporary","memberships","membership_closure"], "Operator capability"); assert.equal(row.name, "mscqr_prod_admin"); const { name, memberships, membership_closure: closure, ...fields } = row; add("operatorCapabilities", name, fields); for (const membership of memberships) { exactKeys(membership, ["role","grantor","admin","inherit","set"], "Operator membership"); const identity = membershipIdentity(name, membership, "member-of"); addUnexpectedRole(membership.role); addUnexpectedRole(membership.grantor); add("operatorMemberships", identity, { present: true }); } for (const inheritedRole of closure) { addUnexpectedRole(inheritedRole); add("operatorInheritedCapabilities", canonicalJson([name, inheritedRole]), { present: true }); } }
  assert.equal(catalogue.operatorCapabilities.length, 1, "Operator capability metadata is incomplete");
  return Object.freeze([...objects.values()].sort((a, b) => a.collection.localeCompare(b.collection) || a.identity.localeCompare(b.identity)).map((entry) => Object.freeze({ ...entry, fields: Object.freeze(entry.fields) })));
}

export function createSecurityRebaselineInventory({ kind, protectedMainSha, candidateSourceSha, catalogue, repositoryRoot, packageChecksums, taskEvidence = null }) {
  assert.ok(["CANONICAL", "LIVE"].includes(kind)); assert.match(protectedMainSha || "", SHA40); assert.match(candidateSourceSha || "", SHA40); assert.equal(Math.trunc(Number(catalogue?.identity?.server_version_num) / 10000), 18, "Security catalogue requires PostgreSQL 18");
  const requirements = createAppOnlyRequirements({ repositoryRoot, sourceSha: protectedMainSha, candidateSourceSha, catalogue, packageChecksums });
  const normalizedCatalogue = kind === "CANONICAL" ? canonicalizeDisposableHarness(catalogue) : catalogue;
  const objects = normalizeSecurityRebaselineCatalogue(normalizedCatalogue, { kind }); if (kind === "CANONICAL") assert.ok(!objects.some(({ collection }) => collection === "unexpectedRoles"), "Canonical inventory contains a non-allowlisted role grant or membership"); const body = { schemaVersion: 1, kind: `PRODUCTION_SECURITY_REBASELINE_${kind}_INVENTORY`, protectedMainSha, candidateSourceSha, postgresqlMajor: 18,
    collectorVersion: SECURITY_REBASELINE_COLLECTOR_VERSION, sourceContractSha256: requirements.sourceContractSha256, migrationSetDigest: requirements.migrationSetDigest,
    packageChecksumsSha256: requirements.canonicalPackageChecksumsSha256, appOnlyRequirementsSha256: requirements.requirementsSha256, catalogueSha256: canonicalSha256(objects), objects, ...(taskEvidence ? { taskEvidence } : {}) };
  assertSecurityMetadata(body); const inventory = Object.freeze({ ...body, artifactSha256: canonicalSha256(body) }); assertSecurityRebaselineInventory(inventory); return inventory;
}
export function createLiveSecurityRebaselineInventory({ protectedMainSha, candidateSourceSha, catalogue, canonical: canonicalInput, taskEvidence }) {
  const canonical = assertSecurityRebaselineInventory(canonicalInput, { protectedMainSha }); assert.equal(canonical.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY"); assert.equal(Math.trunc(Number(catalogue?.identity?.server_version_num) / 10000), canonical.postgresqlMajor, "Live PostgreSQL major mismatch");
  if (candidateSourceSha !== undefined) assert.equal(candidateSourceSha, canonical.candidateSourceSha, "Live candidate differs from canonical requirements identity");
  const objects = normalizeSecurityRebaselineCatalogue(catalogue, { kind: "LIVE" }), body = { schemaVersion: 1, kind: "PRODUCTION_SECURITY_REBASELINE_LIVE_INVENTORY", protectedMainSha, candidateSourceSha: canonical.candidateSourceSha, postgresqlMajor: canonical.postgresqlMajor,
    collectorVersion: canonical.collectorVersion, sourceContractSha256: canonical.sourceContractSha256, migrationSetDigest: canonical.migrationSetDigest,
    packageChecksumsSha256: canonical.packageChecksumsSha256, appOnlyRequirementsSha256: canonical.appOnlyRequirementsSha256, catalogueSha256: canonicalSha256(objects), objects, taskEvidence };
  assertSecurityMetadata(body); const inventory = Object.freeze({ ...body, artifactSha256: canonicalSha256(body) }); assertSecurityRebaselineInventory(inventory); return inventory;
}
export function assertSecurityRebaselineInventory(value, expected = {}) {
  const { artifactSha256, ...body } = value || {}; assert.equal(artifactSha256, canonicalSha256(body)); assert.ok(["PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY","PRODUCTION_SECURITY_REBASELINE_LIVE_INVENTORY"].includes(body.kind));
  exactKeys(body, ["schemaVersion","kind","protectedMainSha","candidateSourceSha","postgresqlMajor","collectorVersion","sourceContractSha256","migrationSetDigest","packageChecksumsSha256","appOnlyRequirementsSha256","catalogueSha256","objects", ...(body.kind.endsWith("LIVE_INVENTORY") ? ["taskEvidence"] : [])], "Security inventory");
  assert.equal(body.schemaVersion, 1); assert.match(body.protectedMainSha || "", SHA40); assert.match(body.candidateSourceSha || "", SHA40); assert.equal(body.postgresqlMajor, 18); assert.equal(body.collectorVersion, SECURITY_REBASELINE_COLLECTOR_VERSION);
  for (const field of ["sourceContractSha256","migrationSetDigest","packageChecksumsSha256","appOnlyRequirementsSha256","catalogueSha256"]) assert.match(body[field] || "", SHA256); if (expected.protectedMainSha) assert.equal(body.protectedMainSha, expected.protectedMainSha); if (expected.candidateSourceSha) assert.equal(body.candidateSourceSha, expected.candidateSourceSha);
  assert.ok(Array.isArray(body.objects) && body.objects.length > 0 && body.objects.length <= 20000); assert.equal(body.catalogueSha256, canonicalSha256(body.objects)); const seen = new Set();
  for (const object of body.objects) { exactKeys(object, ["collection","identity","fields"], "Inventory object"); assert.ok(Object.hasOwn(FIELDS, object.collection)); const key = `${object.collection}\0${object.identity}`; assert.ok(!seen.has(key), "Duplicate inventory identity"); seen.add(key); exactKeys(object.fields, FIELDS[object.collection], "Inventory fields"); }
  if (body.kind.endsWith("LIVE_INVENTORY")) { exactKeys(body.taskEvidence, ["taskArn","taskDefinitionArn","containerName","containerExitCode","probeRuntimeSourceSha","probeImageSourceSha","probeImageDigest","applicationImageSourceSha","applicationImageDigest","requestSha256","verificationContractSha256"], "Live task evidence"); assert.match(body.taskEvidence.taskArn || "", /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task\/[A-Za-z0-9_-]+\/[a-f0-9]{32}$/); assert.match(body.taskEvidence.taskDefinitionArn || "", /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/); assert.match(body.taskEvidence.containerName || "", /^[A-Za-z0-9_-]{1,255}$/); assert.equal(body.taskEvidence.containerExitCode, 0); for (const field of ["probeRuntimeSourceSha","probeImageSourceSha","applicationImageSourceSha"]) assert.match(body.taskEvidence[field] || "", SHA40); assert.equal(body.taskEvidence.probeRuntimeSourceSha, body.protectedMainSha); assert.equal(body.taskEvidence.probeImageSourceSha, body.protectedMainSha); assert.equal(body.taskEvidence.applicationImageSourceSha, body.candidateSourceSha); for (const field of ["probeImageDigest","applicationImageDigest"]) assert.match(body.taskEvidence[field] || "", /^sha256:[a-f0-9]{64}$/); assert.match(body.taskEvidence.requestSha256 || "", SHA256); assert.match(body.taskEvidence.verificationContractSha256 || "", SHA256); }
  assertSecurityMetadata(body); return Object.freeze(value);
}
const operationFor = ({ collection, identity, field, before, after }) => collection === "unexpectedRoles" ? "UNEXPECTED_OBJECT" : field === "owner" ? "OWNERSHIP_CHANGE" : GRANTS.has(collection) ? (before === undefined ? "GRANT" : "REVOKE")
  : ["roles","roleMetadata","roleMemberships","roleMembers","operatorCapabilities","operatorMemberships","operatorInheritedCapabilities"].includes(collection) ? "ROLE_CHANGE"
    : collection === "tables" && field === "rls" && after === true ? "ENABLE_RLS"
      : collection === "tables" && field === "forced" && after === true ? "FORCE_RLS"
        : ["tables","schemas","databases","types","sequences"].includes(collection) && (before === undefined || after === undefined || ["columns","constraints","kind"].includes(field)) ? "UNEXPECTED_OBJECT"
          : before === undefined ? "CREATE" : after === undefined && (collection === "policies" || collection === "routines" && MANAGED_SCHEMAS.has(identity.split(".")[0])) ? "DROP_POLICY_OR_MANAGED_ROUTINE" : after === undefined && collection === "routines" ? "UNEXPECTED_OBJECT" : "ALTER";
const capabilityFor = (operation) => ({ CREATE:"CREATE_SECURITY_OBJECT", ALTER:"ALTER_SECURITY_OBJECT", DROP_POLICY_OR_MANAGED_ROUTINE:"DROP_REVIEWED_SECURITY_OBJECT", GRANT:"GRANT_SECURITY_PRIVILEGE", REVOKE:"REVOKE_SECURITY_PRIVILEGE", ENABLE_RLS:"ALTER_TABLE_OWNER", FORCE_RLS:"ALTER_TABLE_OWNER", OWNERSHIP_CHANGE:"SET_ROLE_AND_ALTER_OWNER", ROLE_CHANGE:"CREATEROLE", UNEXPECTED_OBJECT:"MANUAL_SECURITY_REVIEW" })[operation];
const isBlockingDifference = ({ operation, collection, identity }) => operation === "UNEXPECTED_OBJECT"
  || ["extensions","bindings","triggers","constraintTriggers","rules","eventTriggers","parameterPrivileges","operatorMemberships","operatorInheritedCapabilities"].includes(collection)
  || collection === "defaultPrivileges" && JSON.parse(identity)[1] === "*" && JSON.parse(identity)[3] === "PUBLIC";
export function diffSecurityRebaselineInventories(liveInput, canonicalInput) {
  const live = assertSecurityRebaselineInventory(liveInput), canonical = assertSecurityRebaselineInventory(canonicalInput); assert.equal(live.kind, "PRODUCTION_SECURITY_REBASELINE_LIVE_INVENTORY"); assert.equal(canonical.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY");
  for (const field of ["protectedMainSha","candidateSourceSha","postgresqlMajor","collectorVersion","sourceContractSha256","migrationSetDigest","packageChecksumsSha256","appOnlyRequirementsSha256"]) assert.equal(live[field], canonical[field], `Live/canonical ${field} mismatch`);
  const map = (inventory) => new Map(inventory.objects.map((entry) => [`${entry.collection}\0${entry.identity}`, entry])), before = map(live), after = map(canonical), differences = [];
  for (const key of [...new Set([...before.keys(), ...after.keys()])].sort()) { const observed = before.get(key), expected = after.get(key), collection = (observed || expected).collection, identity = (observed || expected).identity; const fields = observed && expected ? [...new Set([...Object.keys(observed.fields), ...Object.keys(expected.fields)])].sort() : ["__object__"]; for (const field of fields) { const oldValue = field === "__object__" ? observed?.fields : observed?.fields[field], newValue = field === "__object__" ? expected?.fields : expected?.fields[field]; if (observed && expected && canonicalJson(oldValue) === canonicalJson(newValue)) continue; const operation = operationFor({ collection, identity, field, before: observed ? oldValue : undefined, after: expected ? newValue : undefined }); differences.push({ collection, identity, field, operation, beforeSha256: observed ? canonicalSha256(oldValue) : null, afterSha256: expected ? canonicalSha256(newValue) : null, canonicalSourceIdentity: canonical.catalogueSha256, requiredCapability: capabilityFor(operation) }); } }
  differences.sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
  const blockingDifferences = differences.filter(isBlockingDifference);
  const body = { schemaVersion: 1, kind: "PRODUCTION_SECURITY_REBASELINE_DIFF", protectedMainSha: canonical.protectedMainSha, candidateSourceSha: canonical.candidateSourceSha, postgresqlMajor: canonical.postgresqlMajor, collectorVersion: canonical.collectorVersion, sourceContractSha256: canonical.sourceContractSha256, migrationSetDigest: canonical.migrationSetDigest, packageChecksumsSha256: canonical.packageChecksumsSha256, liveArtifactSha256: live.artifactSha256, canonicalArtifactSha256: canonical.artifactSha256, liveCatalogueSha256: live.catalogueSha256, canonicalCatalogueSha256: canonical.catalogueSha256, safeToConstructConvergencePlan: blockingDifferences.length === 0, differenceCount: differences.length, categoryCounts: Object.fromEntries(SECURITY_REBASELINE_OPERATIONS.map((operation) => [operation, differences.filter((item) => item.operation === operation).length])), blockerCount: blockingDifferences.length, differences };
  return Object.freeze({ ...body, artifactSha256: canonicalSha256(body) });
}
export function assertSecurityRebaselineDiff(value) { const { artifactSha256, ...body } = value || {}; assert.equal(artifactSha256, canonicalSha256(body)); exactKeys(body, ["schemaVersion","kind","protectedMainSha","candidateSourceSha","postgresqlMajor","collectorVersion","sourceContractSha256","migrationSetDigest","packageChecksumsSha256","liveArtifactSha256","canonicalArtifactSha256","liveCatalogueSha256","canonicalCatalogueSha256","safeToConstructConvergencePlan","differenceCount","categoryCounts","blockerCount","differences"], "Security diff"); assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_SECURITY_REBASELINE_DIFF"); assert.match(body.protectedMainSha || "", SHA40); assert.match(body.candidateSourceSha || "", SHA40); assert.equal(body.postgresqlMajor, 18); assert.equal(body.collectorVersion, SECURITY_REBASELINE_COLLECTOR_VERSION); for (const field of ["sourceContractSha256","migrationSetDigest","packageChecksumsSha256","liveArtifactSha256","canonicalArtifactSha256","liveCatalogueSha256","canonicalCatalogueSha256"]) assert.match(body[field] || "", SHA256); assert.deepEqual(Object.keys(body.categoryCounts).sort(), [...SECURITY_REBASELINE_OPERATIONS].sort()); assert.equal(body.differences.length, body.differenceCount); for (const difference of body.differences) { exactKeys(difference, ["collection","identity","field","operation","beforeSha256","afterSha256","canonicalSourceIdentity","requiredCapability"], "Security difference"); assert.ok(Object.hasOwn(FIELDS, difference.collection)); assert.match(difference.identity || "", /^.{1,4096}$/s); assert.match(difference.field || "", /^.{1,128}$/s); assert.ok(SECURITY_REBASELINE_OPERATIONS.includes(difference.operation)); for (const digest of [difference.beforeSha256, difference.afterSha256]) if (digest !== null) assert.match(digest, SHA256); assert.equal(difference.canonicalSourceIdentity, body.canonicalCatalogueSha256); assert.match(difference.requiredCapability || "", /^[A-Z][A-Z_]+$/); } assert.equal(body.differenceCount, Object.values(body.categoryCounts).reduce((sum, count) => sum + count, 0)); const blockerCount = body.differences.filter(isBlockingDifference).length; assert.equal(body.blockerCount, blockerCount); assert.equal(body.safeToConstructConvergencePlan, body.blockerCount === 0); assertSecurityMetadata(body); return Object.freeze(value); }
export function securityRebaselineLogSummary(artifact) { if (artifact.kind === "PRODUCTION_SECURITY_REBASELINE_DIFF") { const value = assertSecurityRebaselineDiff(artifact); return Object.freeze({ kind: value.kind, protectedMainSha: value.protectedMainSha, artifactSha256: value.artifactSha256, canonicalCatalogueSha256: value.canonicalCatalogueSha256, differenceCount: value.differenceCount, categoryCounts: value.categoryCounts, blockerCount: value.blockerCount, safeToConstructConvergencePlan: value.safeToConstructConvergencePlan }); } const value = assertSecurityRebaselineInventory(artifact); return Object.freeze({ kind: value.kind, protectedMainSha: value.protectedMainSha, artifactSha256: value.artifactSha256, catalogueSha256: value.catalogueSha256, collectorVersion: value.collectorVersion, collectionCounts: Object.fromEntries([...new Set(value.objects.map(({ collection }) => collection))].sort().map((collection) => [collection, value.objects.filter((entry) => entry.collection === collection).length])) }); }
