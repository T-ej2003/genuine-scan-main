import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { compareProductionSecurityRebaseline } from "../aws/compare-production-security-rebaseline.mjs";
import { assertSemanticallyEmptyRlsProbeOverrides, authenticateCompleteRlsProbeObservation, buildProductionRlsProbeCommand, collectCompleteRlsProbeLogEvents, waitForCompleteRlsProbeObservation } from "../aws/probe-production-rls-catalogue.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { assertSecurityRebaselineInventory, createLiveSecurityRebaselineInventory, createSecurityRebaselineInventory, diffSecurityRebaselineInventories, SECURITY_REBASELINE_COVERAGE, SECURITY_REBASELINE_NORMALIZED_COLLECTIONS, SECURITY_REBASELINE_OPERATIONS } from "../aws/production-security-rebaseline-inventory.mjs";
import { createSecurityCatalogueTransportKeyPair, decryptSecurityCatalogueTransport, encryptSecurityCatalogueTransport } from "../aws/production-security-rebaseline-transport.mjs";
import { assertProductionRlsProbeImageSource, parseProductionRlsProbeRuntimeConfig, PRODUCTION_RLS_PROBE_ENTRYPOINT } from "../aws/production-rls-catalogue-probe-config.mjs";
import { buildSecurityRebaselineImageAuthorization, createProductionSecurityRebaselinePreparationManifest, assertProductionSecurityRebaselinePreparationManifest, verifyProductionSecurityRebaselinePreparationManifest, authenticateProductionSecurityRebaselinePreparation, assertSecurityRebaselineSigningEnvironment, assertPreparationWorkflowArtifacts, SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW, SECURITY_REBASELINE_SIGNING_ALGORITHM, SECURITY_REBASELINE_SIGNING_KEY_ALIAS, SECURITY_REBASELINE_SIGNER_ENVIRONMENT, SECURITY_REBASELINE_SIGNER_JOB_WORKFLOW, SECURITY_REBASELINE_SIGNER_WORKFLOW } from "../aws/production-security-rebaseline-preparation.mjs";
import { assertProductionSecurityRebaselineSignerReadback, verifyProductionSecurityRebaselineSigner } from "../aws/verify-production-security-rebaseline-signer.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";

const root = process.cwd(), sourceSha = "a".repeat(40), digest = "b".repeat(64), role = "mscqr_prd_rls_phase2_app";
const probeIdentity = Object.freeze({ sourceSha, candidateSourceSha: sourceSha, probeRuntimeSourceSha: sourceSha, probeImageSourceSha: sourceSha,
  probeImageDigest: `sha256:${"c".repeat(64)}`, applicationImageSourceSha: sourceSha, applicationImageDigest: `sha256:${"d".repeat(64)}` });
const taskEvidence = (candidateSourceSha = sourceSha, overrides = {}) => ({ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "c".repeat(32), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/security-rebaseline:1", containerName: "production-green-read-only-rls-canary", containerExitCode: 0,
  probeRuntimeSourceSha: sourceSha, probeImageSourceSha: sourceSha, probeImageDigest: probeIdentity.probeImageDigest,
  applicationImageSourceSha: candidateSourceSha, applicationImageDigest: probeIdentity.applicationImageDigest, requestSha256: digest, verificationContractSha256: digest, ...overrides });
const grant = (privilege = "SELECT", grantor = "mscqr_prod_admin") => ({ role, grantor, privilege, grantable: false });
function catalogue() { const table = { name: "User", kind: "r", rls: true, forced: true, owner: "mscqr_prod_admin", view_definition: null, columns: [{ name: "id", type: "text", notNull: true, identity: "", generated: "", default: null, enumLabels: [] }], constraints: [], grants: [grant()], column_grants: [{ column: "id", ...grant() }] }; const policy = { table: "User", name: "user_read", permissive: true, command: "r", roles: [role], using: "id = current_user", check: null }; return { identity: { role:"mscqr_prod_rls_canary_read",session_role:"mscqr_prod_rls_canary_read",database:"mscqr_production_rls_green_phase2",server_version_num:180004,read_only:"on",default_read_only:"on",rolsuper:false,rolinherit:false,rolcreaterole:false,rolcreatedb:false,rolreplication:false,rolbypassrls:false,memberships:false,write_privileges:false,schema_write:false,database_write:false },
  routines: [{ schema: "app_auth", name: "secure", arguments: "value text", result: "boolean", owner: "mscqr_prod_admin", security_definer: true, volatility: "s", parallel: "u", leakproof: false, strict: true, config: ["search_path=pg_catalog"], body: "SELECT true", language: "sql", definition: "CREATE FUNCTION app_auth.secure(value text) RETURNS boolean LANGUAGE sql AS 'SELECT true'", grants: [grant("EXECUTE")] }],
  securityRoutines: [{ schema: "app_auth", name: "secure", arguments: "value text", kind: "f", result: "boolean", owner: "mscqr_prod_admin", security_definer: true, volatility: "s", parallel: "u", leakproof: false, strict: true, config: ["search_path=pg_catalog"], body: "SELECT true", language: "sql", definition: "CREATE FUNCTION app_auth.secure(value text) RETURNS boolean LANGUAGE sql AS 'SELECT true'", aggregate_state_sha256: null, grants: [grant("EXECUTE")] }],
  securityExtensions: [{ name: "plpgsql", version: "1.0", schema: "pg_catalog", relocatable: false, owner: "rdsadmin" }],
  securityBindings: [],
  tables: [structuredClone(table)], securityTables: [{ schema:"public",...structuredClone(table), persistence:"PERMANENT", populated:null, access_method:"heap", of_type:null, view_security_options:[], partition_key:null, partition_bound:null, parents:[], replica_identity:{mode:"DEFAULT",index:null}, behavior_indexes:[], columns:table.columns.map((column)=>({...column,collation:null,foreign_options:[]})) }], securityTriggers: [], securityConstraintTriggers: [], securityRules: [], securityEventTriggers: [],
  policies: [structuredClone(policy)], securityPolicies: [{ schema:"public",...structuredClone(policy) }],
  schemas: [{ name: "public", owner: "mscqr_prod_admin", grants: [] }, { name: "app_auth", owner: "mscqr_prod_admin", grants: [grant("USAGE")] }],
  securitySchemas: [{ name: "public", owner: "mscqr_prod_admin", grants: [] }, { name: "app_auth", owner: "mscqr_prod_admin", grants: [grant("USAGE")] }],
  roles: [{ name: role, login: false, superuser: false, inherit: false, create_role: false, create_database: false, replication: false, bypass_rls: false, memberships: [], members: [] }],
  securityRoles: [{ name: role, login: false, valid_until: null, connection_limit: -1, superuser: false, inherit: false, create_role: false, create_database: false, replication: false, bypass_rls: false, memberships: [], members: [] }, { name: "mscqr_prod_admin", login: true, valid_until: null, connection_limit: -1, superuser: false, inherit: true, create_role: true, create_database: false, replication: false, bypass_rls: true, memberships: [], members: [] }],
  roleMetadata: [{ name: role, comment_present: true, comment_sha256: digest, settings: [{ database: "*", settings: ["row_security=on"] }], unsupported_settings: false }, { name: "mscqr_prod_admin", comment_present: false, comment_sha256: digest, settings: [], unsupported_settings: false }],
  databases: [{ database: "mscqr_production_rls_green_phase2", owner: "mscqr_prod_admin", allow_connections:true, connection_limit:-1, is_template:false, role, grantor: "mscqr_prod_admin", privilege: "CONNECT", grantable: false }],
  defaults: [{ owner: role, schema: "public", object_type: "r", role, grantor: role, privilege: "SELECT", grantable: false }], parameterPrivileges: [],
  types: [{ schema: "public", name: "Status", kind: "e", owner: "mscqr_prod_admin", category:"E", not_null:false, base_type:null, collation:null, default_value:null, default_expression:null, implementation:{input:"enum_in(cstring,oid)",output:"enum_out(anyenum)",receive:"enum_recv(internal,oid)",send:"enum_send(anyenum)",modifier_input:null,modifier_output:null,analyze:null,subscript:null,length:4,by_value:true,alignment:"i",storage:"p",delimiter:",",preferred:false,defined:true,element_type:null,dimensions:0}, composite_attributes:[], range_definition:null, enum_labels:["active"], constraints:[], grants: [grant("USAGE")] }],
  sequences: [{ schema: "public", name: "example_seq", owner: "mscqr_prod_admin", persistence:"PERMANENT", data_type:"bigint", start_value:"1", increment_by:"1", maximum:"9223372036854775807", minimum:"1", cache_size:"1", cycle:false, grants: [grant("USAGE")] }],
  operatorCapabilities: [{ name: "mscqr_prod_admin", login: true, valid_until: null, connection_limit: -1, superuser: false, inherit: true, create_role: true, create_database: false, replication: false, bypass_rls: true, database_connect: true, database_create: false, database_temporary: false, memberships: [], membership_closure: [], set_role_closure: [], set_role_capability_closure: [], admin_option_closure: [] }] }; }
const canonical = (value = catalogue(), candidateSourceSha = sourceSha) => createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha, catalogue: value, repositoryRoot: root, packageChecksums: { fixture: digest } });
const live = (value, target = canonical()) => createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: value, canonical: target, taskEvidence: taskEvidence(target.candidateSourceSha) });

test("identical catalogues have a deterministic zero diff", () => { const target = canonical(), a = diffSecurityRebaselineInventories(live(catalogue(), target), target), reversed = catalogue(); for (const key of Object.keys(reversed)) if (Array.isArray(reversed[key])) reversed[key].reverse(); const b = diffSecurityRebaselineInventories(live(reversed, target), target); assert.equal(a.differenceCount, 0); assert.equal(a.artifactSha256, b.artifactSha256); });

test("canonical disposable membership grantors map only to the production semantic grantor", () => {
  const targetValue = catalogue(), parent = targetValue.securityRoles.find(({ name }) => name === role), admin = targetValue.securityRoles.find(({ name }) => name === "mscqr_prod_admin");
  const harness = { name:"mscqr_p2_test",login:true,valid_until:null,connection_limit:-1,superuser:true,inherit:true,create_role:true,create_database:true,replication:true,bypass_rls:true,memberships:[],members:[] };
  const memberOf = { role,grantor:"mscqr_p2_test",admin:false,inherit:false,set:true }, hasMember = { member:"mscqr_prod_admin",grantor:"mscqr_p2_test",admin:false,inherit:false,set:true };
  admin.memberships=[memberOf]; parent.members=[hasMember]; targetValue.operatorCapabilities[0].memberships=[memberOf]; targetValue.securityRoles.push(harness);
  targetValue.roleMetadata.push({name:"mscqr_p2_test",comment_present:false,comment_sha256:digest,settings:[],unsupported_settings:false});
  const target = canonical(targetValue), liveValue = structuredClone(targetValue);
  liveValue.securityRoles=liveValue.securityRoles.filter(({name})=>name!=="mscqr_p2_test"); liveValue.roleMetadata=liveValue.roleMetadata.filter(({name})=>name!=="mscqr_p2_test");
  for (const entry of [liveValue.securityRoles.find(({name})=>name===role).members[0],liveValue.securityRoles.find(({name})=>name==="mscqr_prod_admin").memberships[0],liveValue.operatorCapabilities[0].memberships[0]]) entry.grantor="rdsadmin";
  const result=diffSecurityRebaselineInventories(live(liveValue,target),target);
  assert.equal(result.differences.filter(({collection})=>["roleMemberships","roleMembers","operatorMemberships"].includes(collection)).length,0);
  const drift=structuredClone(liveValue); for (const entry of [drift.securityRoles.find(({name})=>name===role).members[0],drift.securityRoles.find(({name})=>name==="mscqr_prod_admin").memberships[0],drift.operatorCapabilities[0].memberships[0]]) entry.grantor="mscqr_prod_admin";
  assert.ok(diffSecurityRebaselineInventories(live(drift,target),target).differences.some(({collection})=>collection==="operatorMemberships"));
  const unsupported=structuredClone(targetValue); for (const entry of [unsupported.securityRoles.find(({name})=>name===role).members[0],unsupported.securityRoles.find(({name})=>name==="mscqr_prod_admin").memberships[0],unsupported.operatorCapabilities[0].memberships[0]]) entry.grantor="mscqr_prod_admin";
  assert.throws(()=>canonical(unsupported),/unsupported grantor/);
  const changedOptions=structuredClone(liveValue); changedOptions.operatorCapabilities[0].memberships[0].admin=true;
  assert.ok(diffSecurityRebaselineInventories(live(changedOptions,target),target).differences.some(({collection})=>collection==="operatorMemberships"));
});

test("installed extension identity is deterministic and any extension drift blocks planning", () => {
  const target=canonical();
  for (const mutate of [
    (value)=>value.securityExtensions.push({name:"postgres_fdw",version:"1.1",schema:"public",relocatable:true,owner:"mscqr_prod_admin"}),
    (value)=>value.securityExtensions[0].version="1.1",
    (value)=>value.securityExtensions[0].schema="public",
    (value)=>value.securityExtensions.splice(0,1),
  ]) { const value=catalogue(); mutate(value); const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({collection})=>collection==="extensions")); }
});
test("replication and user-defined security bindings are visible hard stops", () => {
  const target=canonical(); for (const binding of [
    {kind:"publication",name:"unexpected_publication",owner:"mscqr_prod_admin",definition:{all_tables:true,insert:true,update:true,delete:true,truncate:true,via_root:false,generated_columns:"n"}},
    {kind:"operator",name:"public.===(integer,integer)",owner:"mscqr_prod_admin",definition:{result:"boolean",function:"int4eq(integer,integer)",commutator:null,negator:null,merge:false,hash:false}},
    {kind:"foreign_server",name:"unexpected_server",owner:"mscqr_prod_admin",definition:{wrapper:"postgres_fdw",type:"",version:"",options:[{name:"host",value_sha256:digest}],grants:[]}},
  ]) { const value=catalogue(); value.securityBindings.push(binding); const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({collection,identity})=>collection==="bindings"&&identity===`${binding.kind}:${binding.name}`)); }
});
test("parameter ACL, constraint enforcement, publication membership and foreign option digests are security identities", () => {
  const target=canonical(), value=catalogue();
  value.securityBindings.push({kind:"subscription",name:"sub",owner:role,definition:{enabled:false,binary:false,streaming:"f",two_phase:"d",disable_on_error:false,password_required:true,run_as_owner:false,failover:false,slot_name:null,synchronous_commit:"off",publications:["pub"],origin:"any",skip_lsn:"0/16B6C50",connection_info_sha256:digest}});
  value.parameterPrivileges.push({parameter:"session_replication_role",role,grantor:"mscqr_prod_admin",privilege:"SET",grantable:false});
  value.securityConstraintTriggers.push({constraint_schema:"public",constraint_relation:"child",constraint_name:"child_parent_fkey",schema:"public",relation:"child",enabled:"D",function:"pg_catalog.RI_FKey_check_ins()",trigger_type:5,deferrable:false,initially_deferred:false});
  value.securityBindings.push(
    {kind:"publication_relation",name:"pub:public.User",owner:null,definition:{publication:"pub",schema:"public",relation:"User",columns:["id"],row_filter:"(id IS NOT NULL)"}},
    {kind:"foreign_table",name:"public.remote_user",owner:"mscqr_prod_admin",definition:{server:"remote",options:[{name:"table_name",value_sha256:digest}]}}
  );
  const diff=diffSecurityRebaselineInventories(live(value,target),target);
  for (const collection of ["parameterPrivileges","constraintTriggers","bindings"]) assert.ok(diff.differences.some((entry)=>entry.collection===collection));
  assert.equal(diff.safeToConstructConvergencePlan,false);
  const serialized=JSON.stringify(live(value,target)); assert.ok(!serialized.includes("remote-secret-value"));
  const hidden=catalogue(); hidden.securityBindings.push({kind:"user_mapping",name:"remote:user",owner:null,definition:{options_visible:false,options:null}});
  assert.throws(()=>live(hidden,target),/not visible/);
});

test("the explicit collector-to-diff coverage contract is complete", () => {
  const raw = new Set(Object.keys(catalogue())), normalized = new Set(SECURITY_REBASELINE_NORMALIZED_COLLECTIONS);
  for (const entry of SECURITY_REBASELINE_COVERAGE) {
    assert.ok(raw.has(entry.rawCollection), `${entry.surface} has no real collector output`);
    for (const collection of entry.normalizedCollections.split("/"))
      assert.ok(normalized.has(collection), `${entry.surface} has no normalized collection contract for ${collection}`);
  }
});

for (const [label, mutate, expected] of [
  ["policy command", (c) => c.securityPolicies[0].command="a", "ALTER"], ["policy role", (c) => c.securityPolicies[0].roles=["PUBLIC"], "ALTER"], ["USING", (c) => c.securityPolicies[0].using="true", "ALTER"], ["WITH CHECK", (c) => c.securityPolicies[0].check="true", "ALTER"],
  ["RLS enabled", (c) => c.securityTables[0].rls=false, "ENABLE_RLS"], ["RLS forced", (c) => c.securityTables[0].forced=false, "FORCE_RLS"], ["role attribute", (c) => c.securityRoles[0].login=true, "ROLE_CHANGE"], ["membership", (c) => c.securityRoles[0].memberships=[{ role, grantor:"mscqr_prod_admin", admin:false, inherit:true, set:true }], "ROLE_CHANGE"],
  ["ownership", (c) => c.securityTables[0].owner="other", "OWNERSHIP_CHANGE"], ["schema ACL", (c) => c.securitySchemas[1].grants=[], "GRANT"], ["table ACL", (c) => c.securityTables[0].grants=[], "GRANT"], ["function ACL", (c) => c.securityRoutines[0].grants=[], "GRANT"], ["column ACL", (c) => c.securityTables[0].column_grants=[], "GRANT"],
  ["database ACL", (c) => c.databases=[], "GRANT"], ["default privilege", (c) => c.defaults=[], "GRANT"], ["type ACL", (c) => c.types[0].grants=[], "GRANT"], ["sequence ACL", (c) => c.sequences[0].grants=[], "GRANT"],
  ["managed role comment", (c) => c.roleMetadata[0].comment_sha256="d".repeat(64), "ROLE_CHANGE"], ["managed role setting", (c) => c.roleMetadata[0].settings=[], "ROLE_CHANGE"], ["operator capability", (c) => c.operatorCapabilities[0].bypass_rls=false, "ROLE_CHANGE"], ["function security", (c) => c.securityRoutines[0].security_definer=false, "ALTER"],
]) test(`${label} difference is categorized`, () => { const target=canonical(), value=catalogue(); mutate(value); assert.ok(diffSecurityRebaselineInventories(live(value,target),target).differences.some(({operation})=>operation===expected)); });

test("duplicate identities, unsupported fields and unexpected roles fail closed", () => { for (const mutate of [(c)=>c.securityPolicies.push(structuredClone(c.securityPolicies[0])), (c)=>c.securityPolicies[0].extra=true, (c)=>c.roles[0].name="attacker", (c)=>c.roleMetadata[0].unsupported_settings=true]) { const value=catalogue(); mutate(value); assert.throws(()=>canonical(value)); } });
test("canonical inventory keeps protected main and authenticated candidate identities distinct", () => { const candidate="b".repeat(40), same=canonical(catalogue(),sourceSha), ancestor=canonical(catalogue(),candidate); assert.equal(same.protectedMainSha,sourceSha); assert.equal(ancestor.protectedMainSha,sourceSha); assert.equal(ancestor.candidateSourceSha,candidate); assert.notEqual(same.appOnlyRequirementsSha256,ancestor.appOnlyRequirementsSha256); assert.throws(()=>assertSecurityRebaselineInventory(ancestor,{protectedMainSha:"c".repeat(40)})); assert.throws(()=>canonical(catalogue(),"not-a-sha")); const liveAncestor=live(catalogue(),ancestor); assert.equal(liveAncestor.candidateSourceSha,candidate); assert.equal(liveAncestor.taskEvidence.probeImageSourceSha,sourceSha); assert.equal(liveAncestor.taskEvidence.applicationImageSourceSha,candidate); assert.throws(()=>diffSecurityRebaselineInventories({...liveAncestor,candidateSourceSha:sourceSha,artifactSha256:canonicalSha256(Object.fromEntries(Object.entries(liveAncestor).filter(([key])=>key!=="artifactSha256").map(([key,value])=>[key,key==="candidateSourceSha"?sourceSha:value])))},ancestor)); for (const [field,value] of [["probeImageSourceSha",candidate],["applicationImageSourceSha",sourceSha],["probeImageDigest",`sha256:${"e".repeat(64)}`]]) { const changed=structuredClone(liveAncestor); changed.taskEvidence[field]=value; changed.artifactSha256=canonicalSha256(Object.fromEntries(Object.entries(changed).filter(([key])=>key!=="artifactSha256"))); if (field.endsWith("SourceSha")) assert.throws(()=>assertSecurityRebaselineInventory(changed)); else assert.notEqual(changed.artifactSha256,liveAncestor.artifactSha256); } });
test("unexpected business objects hard-stop and cannot become business DML or schema/table DROP", () => { const target=canonical(); for (const mutate of [(c)=>c.securityTables.push({...structuredClone(c.securityTables[0]),name:"Unexpected"}),(c)=>c.securitySchemas.push({name:"unexpected",owner:"mscqr_prod_admin",grants:[]}),(c)=>c.securityRoutines.push({...structuredClone(c.securityRoutines[0]),schema:"public",name:"unexpected"})]) { const value=catalogue(); mutate(value); const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({operation})=>operation==="UNEXPECTED_OBJECT")); } assert.ok(SECURITY_REBASELINE_OPERATIONS.every((value)=>!/(?:INSERT|UPDATE|DELETE|TRUNCATE|DROP_TABLE|DROP_SCHEMA)/.test(value))); });
test("operator capability projections block inherited, SET ROLE and ADMIN OPTION paths", () => { const target=canonical(), value=catalogue(), operator=value.operatorCapabilities[0]; operator.membership_closure=["pg_write_all_data"]; operator.set_role_closure=["pg_write_all_data"]; operator.set_role_capability_closure=["pg_write_all_data"]; operator.admin_option_closure=["pg_write_all_data"]; const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); for (const collection of ["operatorInheritedCapabilities","operatorSetRoles","operatorSetRoleCapabilities","operatorAdminCapabilities"]) assert.ok(diff.differences.some((entry)=>entry.collection===collection), `${collection} must be a blocking projection`); });
test("all normalized role membership topology drift blocks plan construction", () => {
  const target = canonical(), value = catalogue(), parent = value.securityRoles[0], member = value.securityRoles[1];
  const edge = { role: "pg_read_all_data", grantor: "mscqr_prod_admin", admin: false, inherit: true, set: true };
  parent.memberships.push(edge); member.members.push({ member: role, grantor: edge.grantor, admin: edge.admin, inherit: edge.inherit, set: edge.set });
  const diff = diffSecurityRebaselineInventories(live(value, target), target);
  assert.equal(diff.safeToConstructConvergencePlan, false);
  assert.ok(diff.differences.some(({ collection }) => collection === "roleMemberships"));
  assert.ok(diff.differences.some(({ collection }) => collection === "roleMembers"));
});
test("direct operator privilege-attribute drift blocks plan construction", () => { const target=canonical(), value=catalogue(); value.operatorCapabilities[0].create_role=false; const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({collection})=>collection==="operatorCapabilities")); });
test("managed role attribute drift blocks capabilities reachable after SET ROLE", () => { const target=canonical(), value=catalogue(); value.securityRoles[0].bypass_rls=true; const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({collection,field})=>collection==="roles"&&field==="bypass_rls")); });
test("membership grantor changes are retained in the normalized security diff", () => { const targetValue=catalogue(), admin=targetValue.securityRoles.find(({name})=>name==="mscqr_prod_admin"), app=targetValue.securityRoles[0], edge={role,grantor:"mscqr_prod_admin",admin:false,inherit:true,set:true}; admin.memberships=[edge]; app.members.push({member:"mscqr_prod_admin",grantor:"mscqr_prod_admin",admin:false,inherit:true,set:true}); const target=canonical(targetValue), observed=structuredClone(targetValue); observed.securityRoles.find(({name})=>name==="mscqr_prod_admin").memberships[0].grantor=role; observed.securityRoles[0].members[0].grantor=role; const diff=diffSecurityRebaselineInventories(live(observed,target),target); assert.ok(diff.differences.some(({collection,identity,operation})=>collection==="roleMemberships"&&identity.includes(`\"${role}\"`)&&operation==="ROLE_CHANGE")); assert.ok(diff.differences.some(({collection,identity})=>collection==="roleMembers"&&identity.includes(`\"${role}\"`))); });
test("view definitions, triggers, rules and event triggers participate in fail-closed inventory diff", () => { const targetValue=catalogue(); targetValue.securityTables[0].kind="v"; targetValue.securityTables[0].view_definition=" SELECT id FROM app_auth.source"; targetValue.securityTriggers=[{schema:"app_auth",relation:"source",name:"security_guard",enabled:"O",function:"app_auth.guard()",definition:"CREATE TRIGGER security_guard BEFORE INSERT ON app_auth.source FOR EACH ROW EXECUTE FUNCTION app_auth.guard()"}]; const target=canonical(targetValue), changed=structuredClone(targetValue); changed.securityTables[0].view_definition=" SELECT id FROM app_auth.other_source"; changed.securityTriggers[0].function="app_auth.other_guard()"; changed.securityRules=[{schema:"app_auth",relation:"source",name:"rewrite",event:"3",enabled:"O",definition:"CREATE RULE rewrite AS ON UPDATE TO app_auth.source DO ALSO NOTHING"}]; changed.securityEventTriggers=[{name:"protect_ddl",owner:"mscqr_prod_admin",event:"ddl_command_start",enabled:"O",tags:null,function:"app_auth.protect_ddl()"}]; const diff=diffSecurityRebaselineInventories(live(changed,target),target); assert.ok(diff.differences.some(({collection,field})=>collection==="tables"&&field==="view_definition")); assert.ok(diff.differences.some(({collection,field})=>collection==="triggers"&&field==="function")); assert.ok(diff.differences.some(({collection})=>collection==="rules")); assert.ok(diff.differences.some(({collection})=>collection==="eventTriggers")); assert.equal(diff.safeToConstructConvergencePlan,false); });
test("ACL grantor is part of every normalized grant identity and PUBLIC keeps its grantor", () => { const targetValue=catalogue(); targetValue.securityRoutines[0].grants[0].grantor="mscqr_prod_admin"; targetValue.securityTables[0].grants[0].role="PUBLIC"; targetValue.securityTables[0].column_grants[0].grantor="mscqr_prod_admin"; targetValue.securitySchemas[1].grants[0].grantor="mscqr_prod_admin"; targetValue.types[0].grants[0].grantor="mscqr_prod_admin"; targetValue.sequences[0].grants[0].grantor="mscqr_prod_admin"; const target=canonical(targetValue), changed=structuredClone(targetValue); changed.securityRoutines[0].grants[0].grantor=role; changed.securityTables[0].grants[0].grantor=role; changed.securityTables[0].column_grants[0].grantor=role; changed.securitySchemas[1].grants[0].grantor=role; changed.databases[0].grantor=role; changed.defaults[0].grantor="mscqr_prod_admin"; changed.types[0].grants[0].grantor=role; changed.sequences[0].grants[0].grantor=role; const diff=diffSecurityRebaselineInventories(live(changed,target),target); for (const collection of ["routineGrants","tableGrants","columnGrants","schemaGrants","databaseGrants","defaultPrivileges","typeGrants","sequenceGrants"]) assert.ok(diff.differences.some((entry)=>entry.collection===collection), `${collection} grantor drift is observable`); const publicIdentity=diff.differences.find(({identity})=>identity.includes("PUBLIC")); assert.ok(publicIdentity?.identity.includes("mscqr_prod_admin")); });
test("collector-version changes reject stale canonical inventories", () => { const stale=structuredClone(canonical()); stale.collectorVersion="production-security-catalogue-v4"; const {artifactSha256: _old, ...body}=stale; stale.artifactSha256=canonicalSha256(body); assert.throws(()=>assertSecurityRebaselineInventory(stale)); });
test("global PUBLIC default privileges are visible and block plan construction", () => { const target=canonical(), value=catalogue(); value.defaults.push({ owner:"mscqr_prod_admin", schema:"*", object_type:"r", role:"PUBLIC", grantor:"mscqr_prod_admin", privilege:"SELECT", grantable:false }); const diff=diffSecurityRebaselineInventories(live(value,target),target); assert.equal(diff.safeToConstructConvergencePlan,false); assert.ok(diff.differences.some(({collection,identity})=>collection==="defaultPrivileges"&&identity.includes('"*"')&&identity.includes('"PUBLIC"'))); });
test("aggregate implementation digest participates in deterministic routine diff", () => { const targetValue=catalogue(); Object.assign(targetValue.securityRoutines[0],{kind:"a",definition:null,aggregate_state_sha256:"c".repeat(64)}); const target=canonical(targetValue), value=structuredClone(targetValue); value.securityRoutines[0].aggregate_state_sha256="d".repeat(64); assert.ok(diffSecurityRebaselineInventories(live(value,target),target).differences.some(({collection,field,operation})=>collection==="routines"&&field==="aggregate_state_sha256"&&operation==="ALTER")); });
test("source-contract, migration and PostgreSQL major mismatches fail closed", () => { const target=canonical(), observed=live(catalogue(),target); for (const field of ["sourceContractSha256","migrationSetDigest","collectorVersion"]) { const changed=structuredClone(observed); changed[field]=field==="collectorVersion"?"wrong":digest; changed.artifactSha256=crypto.createHash("sha256").update(JSON.stringify(changed)).digest("hex"); assert.throws(()=>diffSecurityRebaselineInventories(changed,target)); } const value=catalogue(); value.identity.server_version_num=170000; assert.throws(()=>canonical(value)); });
test("secret-shaped fields and values cannot enter artifacts", () => { const value=catalogue(); value.securityPolicies[0][["pass","word"].join("")]="forbidden"; assert.throws(()=>canonical(value)); value.securityPolicies[0]=catalogue().securityPolicies[0]; value.securityPolicies[0].using=["postgresql","://name:value@example"].join(""); assert.throws(()=>canonical(value)); });

test("encrypted catalogue transport is complete, private and substitution-resistant", () => { const keys=createSecurityCatalogueTransportKeyPair(), binding={sourceSha,candidateSourceSha:sourceSha,requirementsSha256:digest}, value={catalogue:catalogue(),padding:crypto.randomBytes(300000).toString("hex")}, chunks=encryptSecurityCatalogueTransport(value,keys.publicKeyPem,binding); assert.deepEqual(decryptSecurityCatalogueTransport(chunks,keys.privateKeyPem,binding),value); assert.ok(!chunks.join("").includes("app_auth")); assert.throws(()=>decryptSecurityCatalogueTransport(chunks.slice(1),keys.privateKeyPem,binding)); assert.throws(()=>decryptSecurityCatalogueTransport([...chunks,chunks[0]],keys.privateKeyPem,binding)); assert.throws(()=>decryptSecurityCatalogueTransport(chunks,keys.privateKeyPem,{...binding,candidateSourceSha:"c".repeat(40)})); });
test("fixed module launch keeps structured configuration as data and contains no dynamic execution", () => {
  const keys = createSecurityCatalogueTransportKeyPair(), requirements = { requirementsSha256: digest, candidateSourceSha: sourceSha };
  const identity = { ...probeIdentity, databaseHostname: "example.invalid" };
  const launch = buildProductionRlsProbeCommand(requirements, identity, { securityTransportPublicKey: keys.publicKeyPem });
  assert.deepEqual(launch.entryPoint, ["node", PRODUCTION_RLS_PROBE_ENTRYPOINT]); assert.deepEqual(launch.command, []);
  const config = JSON.parse(launch.environment[0].value);
  assert.equal(config.sourceSha, sourceSha); assert.equal(config.candidateSourceSha, sourceSha);
  assert.equal(config.requirementsSha256, digest); assert.equal(config.databaseHostname, "example.invalid");
  assert.match(config.securityTransportPublicKey, /BEGIN PUBLIC KEY/); assert.equal(Object.hasOwn(config, "privateKey"), false);
  assert.throws(() => buildProductionRlsProbeCommand(requirements, { ...identity, candidateSourceSha: "c".repeat(40) }));
  for (const source of ["scripts/aws/probe-production-rls-catalogue.mjs", "scripts/aws/production-rls-catalogue-probe-runtime.mjs"])
    assert.doesNotMatch(fs.readFileSync(source, "utf8"), /\beval\s*\(|new Function|vm\.run/);
  const probeSource = fs.readFileSync("scripts/aws/probe-production-rls-catalogue.mjs", "utf8");
  assert.match(probeSource, /import os from ["']node:os["']/); assert.match(probeSource, /os\.tmpdir\(\)/);
  const runtime = fs.readFileSync("scripts/aws/production-rls-catalogue-probe-runtime.mjs", "utf8");
  assert.match(runtime, /readFileSync\("\/app\/image-source\.json"/); assert.match(runtime, /assertProductionRlsProbeImageSource/);
});

test("protected preparation producer binds exact PG18 artifacts, image publication, KMS authorization, and manifest", async () => {
  const { produceSecurityRebaselinePreparation } = await import("../aws/produce-production-security-rebaseline-preparation.mjs");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "security-rebaseline-preparation-test-"));
  try {
    const source = sourceSha, runId = "77", imageDigest = `sha256:${"e".repeat(64)}`;
    const requirements = createAppOnlyRequirements({ repositoryRoot: root, sourceSha: source, candidateSourceSha: source, catalogue: catalogue(), packageChecksums: { fixture: digest } });
    const canonicalInventory = canonical(catalogue(), source);
    const requirementsBytes = Buffer.from(JSON.stringify(requirements));
    const canonicalBytes = Buffer.from(JSON.stringify(canonicalInventory));
    const publicationBytes = Buffer.from(`${JSON.stringify({ service: "backend", repository: "mscqr-backend", image_tag: `${source}-backend-only`, image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:${source}-backend-only`, image_digest: imageDigest, image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageDigest}` })}\n`);
    const files = { requirements: path.join(directory, "requirements.json"), canonical: path.join(directory, "canonical.json"), publication: path.join(directory, "publication.jsonl"), manifest: path.join(directory, "manifest.json") };
    fs.writeFileSync(files.requirements, requirementsBytes, { mode: 0o600 }); fs.writeFileSync(files.canonical, canonicalBytes, { mode: 0o600 }); fs.writeFileSync(files.publication, publicationBytes, { mode: 0o600 });
    const reference = (artifactId, bytes) => ({ sourceSha: source, runId, runAttempt: "1", artifactId, artifactDigest: `sha256:${digest}`, fileSha256: crypto.createHash("sha256").update(bytes).digest("hex") });
    const publicationReference = { workflowFile: SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW, ...reference("103", publicationBytes) };
    const env = { GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_REPOSITORY_ID: "1145608538", GITHUB_REPOSITORY_OWNER_ID: "183396573",
      GITHUB_REF: "refs/heads/main", GITHUB_SHA: source, GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: runId, GITHUB_WORKFLOW_REF: `T-ej2003/genuine-scan-main/${SECURITY_REBASELINE_SIGNER_WORKFLOW}@refs/heads/main`, GITHUB_ACTOR: "T-ej2003",
      REQUIREMENTS_FILE: files.requirements, CANONICAL_FILE: files.canonical, PUBLICATION_FILE: files.publication, MANIFEST_OUTPUT: files.manifest, EXPECTED_IMAGE_REF: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageDigest}`,
      REQUIREMENTS_REFERENCE_JSON: JSON.stringify(reference("101", requirementsBytes)), CANONICAL_REFERENCE_JSON: JSON.stringify(reference("102", canonicalBytes)), PUBLICATION_REFERENCE_JSON: JSON.stringify(publicationReference) };
    const result = produceSecurityRebaselinePreparation({ sourceSha: source, repositoryRoot: root, env, sign: ({ keyArn, signingAlgorithm, messageType, digest: signedDigest }) => {
      assert.equal(keyArn, SECURITY_REBASELINE_SIGNING_KEY_ALIAS); assert.equal(signingAlgorithm, SECURITY_REBASELINE_SIGNING_ALGORITHM); assert.equal(messageType, "DIGEST"); assert.equal(signedDigest.length, 32); return Buffer.alloc(384, 7).toString("base64");
    } });
    const manifest = JSON.parse(fs.readFileSync(files.manifest, "utf8"));
    assert.equal(result.manifestSha256, manifest.manifestSha256); assert.equal(manifest.protectedMainSha, source); assert.equal(manifest.candidateSourceSha, source);
    assert.equal(manifest.candidateImage.digest, imageDigest); assert.equal(manifest.probeRuntime.imageDigest, imageDigest);
    assert.equal(manifest.requirements.requirementsSha256, requirements.requirementsSha256); assert.equal(manifest.canonicalInventory.catalogueSha256, canonicalInventory.catalogueSha256);
    assert.deepEqual(manifest.publicationReference, publicationReference); assert.equal(manifest.subscriptionProjection.presence, "VERIFY_IN_SINGLE_READ_ONLY_PROBE_BEFORE_INVENTORY");
    const verified = verifyProductionSecurityRebaselinePreparationManifest(manifest, { protectedMainSha: source, candidateSourceSha: source, workflowRunId: runId, workflowRunAttempt: "1" }, { verifyImageAuthorization: () => true });
    assert.equal(verified.manifestSha256, result.manifestSha256);
    const manifestBytes = fs.readFileSync(files.manifest);
    const manifestReference = { sourceSha: source, runId, runAttempt: "1", artifactId: "104", artifactDigest: `sha256:${digest}`, fileSha256: crypto.createHash("sha256").update(manifestBytes).digest("hex") };
    const authenticated = authenticateProductionSecurityRebaselinePreparation({ manifestBytes, manifestReference, requirementsBytes, requirementsReference: manifest.requirements.reference,
      canonicalInventoryBytes: canonicalBytes, canonicalReference: manifest.canonicalInventory.reference, publicationBytes, publicationReference,
      sourceSha: source, verifyImageAuthorization: () => true, repositoryRoot: root });
    assert.equal(authenticated.canonicalInventory.catalogueSha256, canonicalInventory.catalogueSha256);
    assert.equal(authenticated.publicationImage.image_ref, manifest.candidateImage.authorization.image.digest.replace(/^sha256:/, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:`));
    const wrongProjection = structuredClone(manifest);
    wrongProjection.subscriptionProjection.expectedDefinitionSha256 = "f".repeat(64);
    const { manifestSha256: _oldSha, ...wrongProjectionBody } = wrongProjection;
    wrongProjection.manifestSha256 = canonicalSha256(wrongProjectionBody);
    const wrongProjectionBytes = Buffer.from(JSON.stringify(wrongProjection));
    assert.throws(() => authenticateProductionSecurityRebaselinePreparation({ manifestBytes: wrongProjectionBytes,
      manifestReference: { ...manifestReference, fileSha256: crypto.createHash("sha256").update(wrongProjectionBytes).digest("hex") },
      requirementsBytes, requirementsReference: manifest.requirements.reference, canonicalInventoryBytes: canonicalBytes,
      canonicalReference: manifest.canonicalInventory.reference, publicationBytes, publicationReference,
      sourceSha: source, verifyImageAuthorization: () => true, repositoryRoot: root }));
    assert.throws(() => authenticateProductionSecurityRebaselinePreparation({ manifestBytes, manifestReference, requirementsBytes, requirementsReference: { ...manifest.requirements.reference, artifactId: "999" }, canonicalInventoryBytes: canonicalBytes, canonicalReference: manifest.canonicalInventory.reference, publicationBytes, publicationReference, sourceSha: source, verifyImageAuthorization: () => true, repositoryRoot: root }));
    assert.throws(() => verifyProductionSecurityRebaselinePreparationManifest(manifest, { workflowRunId: "78" }, { verifyImageAuthorization: () => true }));
    assert.throws(() => verifyProductionSecurityRebaselinePreparationManifest(manifest, {}, { verifyImageAuthorization: () => false }));
    const changed = structuredClone(manifest); changed.candidateImage.digest = `sha256:${"f".repeat(64)}`;
    assert.throws(() => assertProductionSecurityRebaselinePreparationManifest(changed));
    assert.throws(() => verifyProductionSecurityRebaselinePreparationManifest(manifest, { now: Date.parse(manifest.candidateImage.authorization.expiresAt) + 1 }, { verifyImageAuthorization: () => true }));
    assert.equal(manifest.candidateImage.authorization.purpose, "READ_ONLY_PRODUCTION_SECURITY_REBASELINE");
    assert.equal(manifest.candidateImage.authorization.signatureBase64, Buffer.alloc(384, 7).toString("base64"));

    const malformedPublication = Buffer.from(publicationBytes.toString().replace(`"image_digest":"${imageDigest}"`, `"image_digest":"${"e".repeat(64)}"`));
    fs.writeFileSync(files.publication, malformedPublication);
    assert.throws(() => produceSecurityRebaselinePreparation({ sourceSha: source, repositoryRoot: root,
      env: { ...env, MANIFEST_OUTPUT: path.join(directory, "malformed-manifest.json"),
        PUBLICATION_REFERENCE_JSON: JSON.stringify({ ...publicationReference, fileSha256: crypto.createHash("sha256").update(malformedPublication).digest("hex") }) },
      sign: () => assert.fail("Malformed publisher digest must fail before KMS signing") }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("signing environment and purpose-specific OIDC/KMS source contracts fail closed", () => {
  const environment = { name: SECURITY_REBASELINE_SIGNER_ENVIRONMENT, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "Team", reviewer: { id: 1 } }] }, { type: "branch_policy" }], deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } };
  assert.equal(assertSecurityRebaselineSigningEnvironment(environment), true);
  for (const changed of [{ ...environment, protection_rules: [] }, { ...environment, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{}] }] }, { ...environment, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }]) assert.throws(() => assertSecurityRebaselineSigningEnvironment(changed));
  const signingWorkflow = fs.readFileSync(".github/workflows/sign-production-security-rebaseline.yml", "utf8");
  const preparationWorkflow = fs.readFileSync(".github/workflows/prepare-production-security-rebaseline.yml", "utf8");
  assert.doesNotMatch(`${signingWorkflow}\n${preparationWorkflow}`, /administration:\s*read|environments\/[^\s]+\/(?:variables|secrets)/);
  assert.match(signingWorkflow, /gh api .*\/environments\/production-security-rebaseline-signing/);
  assert.match(signingWorkflow, /permissions:\s*\n\s*contents: read\n\s*actions: read/);
  assert.match(preparationWorkflow, /sign-and-manifest:[\s\S]*?permissions:\s*\n\s*contents: read\n\s*actions: read\n\s*id-token: write/);
  assert.match(signingWorkflow, /role-to-assume: \$\{\{ vars\.PRODUCTION_SECURITY_REBASELINE_SIGNER_ROLE_ARN \}\}/);
  const trust = JSON.parse(fs.readFileSync("infra/aws/terraform/production-security-rebaseline-signer/trust-policy.json", "utf8"));
  const condition = trust.Statement[0].Condition.StringEquals;
  assert.equal(trust.Statement[0].Principal.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
  assert.equal(condition["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
  assert.equal(condition["token.actions.githubusercontent.com:sub"], `repo:T-ej2003/genuine-scan-main:environment:${SECURITY_REBASELINE_SIGNER_ENVIRONMENT}`);
  assert.equal(condition["token.actions.githubusercontent.com:repository_id"], "1145608538"); assert.equal(condition["token.actions.githubusercontent.com:repository_owner_id"], "183396573");
  assert.equal(condition["token.actions.githubusercontent.com:ref"], "refs/heads/main"); assert.equal(condition["token.actions.githubusercontent.com:job_workflow_ref"], `T-ej2003/genuine-scan-main/${SECURITY_REBASELINE_SIGNER_JOB_WORKFLOW}@refs/heads/main`);
  const terraform = fs.readFileSync("infra/aws/terraform/production-security-rebaseline-signer/main.tf", "utf8");
  assert.match(terraform, /Action\s*=\s*\["kms:Sign"\]/); assert.match(terraform, /Resource\s*=\s*aws_kms_key\.image_authorization\.arn/);
  assert.doesNotMatch(terraform.match(/resource "aws_iam_role_policy" "sign_only"[\s\S]*?\n}/)?.[0] || "", /kms:\*/);
  assert.match(terraform, /max_session_duration\s*=\s*3600/);
  const signerPolicy = terraform.match(/resource "aws_iam_role_policy" "sign_only"[\s\S]*?\n}/)?.[0] || "";
  assert.equal((signerPolicy.match(/Action\s*=/g) || []).length, 1);
  assert.doesNotMatch(signerPolicy, /Resource\s*=\s*"\*"/);
  assert.doesNotMatch(signerPolicy, /iam:|ecr:|ecs:|rds:|secretsmanager:/);
  assert.match(terraform, /kms:SigningAlgorithm/); assert.match(terraform, /kms:MessageType/); assert.match(terraform, /kms:RequestAlias/);
  const workflow = fs.readFileSync(".github/workflows/prepare-production-security-rebaseline.yml", "utf8");
  const signerWorkflow = fs.readFileSync(".github/workflows/sign-production-security-rebaseline.yml", "utf8");
  assert.match(workflow, /uses: \.\/\.github\/workflows\/sign-production-security-rebaseline\.yml/);
  assert.match(signerWorkflow, /workflow_call:/); assert.match(signerWorkflow, new RegExp(`environment: ${SECURITY_REBASELINE_SIGNER_ENVIRONMENT}`));
  assert.match(signerWorkflow, /aws-actions\/configure-aws-credentials@v6/); assert.match(signerWorkflow, /id-token: write/); assert.match(signerWorkflow, /role-duration-seconds: 3600/);
  assert.match(signerWorkflow, /READY_FOR_READ_ONLY_PROBE=true/); assert.match(signerWorkflow, /retention-days: 90/);
  assert.match(signerWorkflow, /test "\$SOURCE_SHA" = "\$GITHUB_SHA"/); assert.match(signerWorkflow, /test "\$SOURCE_SHA" = "\$\(gh api[^\n]+branches\/main/);
  assert.doesNotMatch(signerWorkflow, /aws-access-key-id:|aws-secret-access-key:|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
  assert.doesNotMatch(`${workflow}\n${signerWorkflow}`, /ecs run-task|production:rls-catalogue-probe|production:apply/);
  const environmentContract = JSON.parse(fs.readFileSync("infra/aws/terraform/production-security-rebaseline-signer/github-environment-contract.json", "utf8"));
  assert.equal(environmentContract.name, SECURITY_REBASELINE_SIGNER_ENVIRONMENT);
  assert.equal(environmentContract.signingJobWorkflow, `.github/workflows/sign-production-security-rebaseline.yml`);
  assert.equal(environmentContract.requiredReviewers, true); assert.equal(environmentContract.preventSelfReview, true);
  assert.deepEqual(environmentContract.variables, ["PRODUCTION_SECURITY_REBASELINE_SIGNER_ROLE_ARN"]);
  assert.deepEqual(environmentContract.forbiddenSecrets, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]);
});

test("signer readback detects trust, permission, key, alias and grant drift", () => {
  const trust = JSON.parse(fs.readFileSync("infra/aws/terraform/production-security-rebaseline-signer/trust-policy.json", "utf8"));
  const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-security-rebaseline-image-signer";
  const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/00000000-0000-4000-8000-000000000001";
  const keyAlias = "alias/mscqr-production-security-rebaseline-image-evidence";
  const signerPolicy = { Version: "2012-10-17", Statement: [{ Sid: "SignPurposeSpecificAuthorizationDigestsOnly", Effect: "Allow", Action: "kms:Sign", Resource: keyArn,
    Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": keyAlias } } }] };
  const keyPolicy = { Version: "2012-10-17", Statement: [
    { Sid: "AccountBreakGlassAdministration", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "kms:*", Resource: "*" },
    { Sid: "ProtectedWorkflowImageAuthorizationSigningOnly", Effect: "Allow", Principal: { AWS: roleArn }, Action: "kms:Sign", Resource: "*",
      Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": keyAlias } } },
  ] };
  const fixture = { role: { RoleName: "mscqr-production-security-rebaseline-image-signer", Arn: roleArn, MaxSessionDuration: 3600, AssumeRolePolicyDocument: trust },
    signerPolicy, attachedPolicies: [], inlinePolicyNames: ["ProductionSecurityRebaselineImageAuthorizationSignOnly"],
    key: { Arn: keyArn, KeyId: keyArn.split("/").at(-1), KeyState: "Enabled", KeyManager: "CUSTOMER", KeyUsage: "SIGN_VERIFY", KeySpec: "RSA_3072", Origin: "AWS_KMS", MultiRegion: false },
    keyPolicy, aliases: [{ AliasName: keyAlias, TargetKeyId: keyArn.split("/").at(-1) }], grants: [] };
  const result = assertProductionSecurityRebaselineSignerReadback(fixture);
  assert.equal(result.unexpectedGrantCount, 0); assert.match(result.signerPolicySha256, /^[a-f0-9]{64}$/);
  const calls = [];
  const readback = verifyProductionSecurityRebaselineSigner({ profile: "readback-test", run: (_command, args) => {
    assert.equal(_command, "aws");
    calls.push(args.slice(0, 2).join(" "));
    if (args[0] === "sts") return { Account: "368992683803" };
    if (args[0] === "iam" && args[1] === "get-role") return { Role: fixture.role };
    if (args[0] === "iam" && args[1] === "list-role-policies") return { PolicyNames: fixture.inlinePolicyNames };
    if (args[0] === "iam" && args[1] === "list-attached-role-policies") return { AttachedPolicies: [] };
    if (args[0] === "iam" && args[1] === "get-role-policy") return { PolicyDocument: fixture.signerPolicy };
    if (args[0] === "kms" && args[1] === "describe-key") return { KeyMetadata: fixture.key };
    if (args[0] === "kms" && args[1] === "get-key-policy") return { Policy: JSON.stringify(fixture.keyPolicy) };
    if (args[0] === "kms" && args[1] === "list-aliases") return { Aliases: fixture.aliases };
    if (args[0] === "kms" && args[1] === "list-grants") return { Grants: [] };
    assert.fail(`Unexpected readback API ${args.slice(0, 2).join(" ")}`);
  } });
  assert.equal(readback.keyArn, keyArn);
  assert.deepEqual(calls, ["sts get-caller-identity", "iam get-role", "iam list-role-policies", "iam list-attached-role-policies",
    "iam get-role-policy", "kms describe-key", "kms get-key-policy", "kms list-aliases", "kms list-grants"]);
  for (const changed of [
    { role: { ...fixture.role, MaxSessionDuration: 7200 } },
    { role: { ...fixture.role, AssumeRolePolicyDocument: { ...trust, Statement: [] } } },
    { signerPolicy: { ...signerPolicy, Statement: [{ ...signerPolicy.Statement[0], Action: "kms:Decrypt" }] } },
    { attachedPolicies: ["arn:aws:iam::aws:policy/AdministratorAccess"] },
    { key: { ...fixture.key, KeySpec: "RSA_2048" } },
    { aliases: [{ AliasName: keyAlias, TargetKeyId: "substituted" }] },
    { grants: [{ GranteePrincipal: "arn:aws:iam::368992683803:role/other", Operations: ["Sign"] }] },
  ]) assert.throws(() => assertProductionSecurityRebaselineSignerReadback({ ...fixture, ...changed }));
});

test("preparation artifact IDs, archive digests, repository privacy, run, and source are authenticated before signing", () => {
  const reference = (artifactId) => ({ sourceSha, runId: "77", runAttempt: "1", artifactId, artifactDigest: `sha256:${digest}`, fileSha256: digest });
  const requirementsReference = reference("101"), canonicalReference = reference("102"), publicationReference = { workflowFile: SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW, ...reference("103") };
  const run = { id: 77, run_attempt: 1, head_sha: sourceSha, head_branch: "main", event: "workflow_dispatch", path: SECURITY_REBASELINE_SIGNER_WORKFLOW,
    repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main", private: true },
    head_repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main", private: true } };
  const artifact = (id, name) => ({ id, name, digest: `sha256:${digest}`, expired: false,
    workflow_run: { id: 77, head_sha: sourceSha, repository_id: 1145608538, head_repository_id: 1145608538 } });
  const artifacts = [artifact(101, "production-security-rebaseline-requirements"), artifact(102, "production-security-rebaseline-canonical"), artifact(103, "production-security-rebaseline-image-publication")];
  const expected = { run, artifacts, sourceSha, runId: "77", runAttempt: "1", requirementsReference, canonicalReference, publicationReference };
  assert.equal(assertPreparationWorkflowArtifacts(expected), true);
  for (const attack of [
    { run: { ...run, head_sha: "f".repeat(40) } },
    { run: { ...run, path: ".github/workflows/other.yml" } },
    { run: { ...run, repository: { ...run.repository, private: false } } },
    { artifacts: artifacts.map((value) => value.id === 103 ? { ...value, digest: `sha256:${"f".repeat(64)}` } : value) },
    { artifacts: artifacts.map((value) => value.id === 103 ? { ...value, expired: true } : value) },
    { artifacts: [...artifacts, artifacts[0]] },
  ]) assert.throws(() => assertPreparationWorkflowArtifacts({ ...expected, ...attack }));
});
test("runtime configuration rejects hostile code-shaped values and unknown keys", () => { const valid={schemaVersion:1,...probeIdentity,requirementsSha256:digest,databaseHostname:"example.invalid",securityTransportPublicKey:null}; assert.deepEqual(parseProductionRlsProbeRuntimeConfig(JSON.stringify(valid)),valid); const attacks=["'\\\n\u2028\u2029${process.exit(9)};()","`;require('node:child_process')()","{\"sourceSha\":\"attacker\"}",Buffer.from("process.exit(9)").toString("base64")]; for (const value of attacks) { for (const field of ["sourceSha","candidateSourceSha","probeRuntimeSourceSha","probeImageSourceSha","probeImageDigest","applicationImageSourceSha","applicationImageDigest","requirementsSha256","databaseHostname","securityTransportPublicKey"]) { const changed={...valid,[field]:value}; assert.throws(()=>parseProductionRlsProbeRuntimeConfig(JSON.stringify(changed))); } } assert.throws(()=>parseProductionRlsProbeRuntimeConfig(JSON.stringify({...valid,code:"process.exit(9)"}))); });
test("probe image source comes from the immutable baked identity, not mutable task environment", () => { assert.equal(assertProductionRlsProbeImageSource(JSON.stringify({gitSha:sourceSha}),sourceSha),true); assert.throws(()=>assertProductionRlsProbeImageSource(JSON.stringify({gitSha:"c".repeat(40)}),sourceSha)); assert.throws(()=>assertProductionRlsProbeImageSource(JSON.stringify({gitSha:sourceSha,sourceSha}),sourceSha)); });
test("fixed launch normalization accepts only observed inert overrides", () => { assert.equal(assertSemanticallyEmptyRlsProbeOverrides({containerOverrides:[{name:"production-green-read-only-rls-canary"}],inferenceAcceleratorOverrides:[]},"production-green-read-only-rls-canary"),true); for (const value of [{containerOverrides:[{name:"wrong"}],inferenceAcceleratorOverrides:[]},{containerOverrides:[{name:"production-green-read-only-rls-canary",command:["true"]}],inferenceAcceleratorOverrides:[]},{containerOverrides:[{name:"production-green-read-only-rls-canary"}],inferenceAcceleratorOverrides:[{deviceName:"x",deviceType:"y"}]}]) assert.throws(()=>assertSemanticallyEmptyRlsProbeOverrides(value,"production-green-read-only-rls-canary")); });
test("log pagination handles empty and partial pages and fails closed", () => { assert.deepEqual(collectCompleteRlsProbeLogEvents([{events:[],requestToken:undefined,nextForwardToken:"a"},{events:[{message:"one"}],requestToken:"a",nextForwardToken:"b"},{events:[],requestToken:"b",nextForwardToken:"b"}]),["one"]); assert.throws(()=>collectCompleteRlsProbeLogEvents([{events:[],requestToken:undefined,nextForwardToken:"a"}])); });
test("CloudWatch completion waits for authenticated terminal evidence and every declared chunk", () => { const keys=createSecurityCatalogueTransportKeyPair(), transportBinding={sourceSha,candidateSourceSha:sourceSha,requirementsSha256:digest}, chunks=encryptSecurityCatalogueTransport({padding:crypto.randomBytes(300000).toString("hex")},keys.publicKeyPem,transportBinding); assert.ok(chunks.length>1); const first=JSON.parse(chunks[0]), body={schemaVersion:1,kind:"PRODUCTION_RLS_CATALOGUE_PROBE",...probeIdentity,requirementsSha256:digest,databaseRole:APP_ONLY_VERIFIER.databaseRole,catalogue:{routines:[],tables:[],policies:[],schemas:[],roles:[]},securityTransport:{transportSha256:first.transportSha256,count:first.count}}, terminal=JSON.stringify({...body,evidenceSha256:canonicalSha256(body)}), options={...probeIdentity,requirementsSha256:digest,securityMode:true}; assert.equal(authenticateCompleteRlsProbeObservation([chunks[0]],options),null,"chunks alone wait"); assert.equal(authenticateCompleteRlsProbeObservation([terminal,...chunks.slice(0,-1)],options),null,"terminal before final chunk waits"); assert.equal(authenticateCompleteRlsProbeObservation([...chunks],options),null,"all chunks before terminal wait"); const complete=authenticateCompleteRlsProbeObservation([...chunks,terminal],options); assert.equal(complete.chunks.length,chunks.length); assert.throws(()=>authenticateCompleteRlsProbeObservation([...chunks,chunks[0],terminal],options)); assert.throws(()=>authenticateCompleteRlsProbeObservation([...chunks,terminal,terminal],options)); const forged=JSON.stringify({...JSON.parse(terminal),sourceSha:"f".repeat(40)}), mismatchedChunk=JSON.parse(chunks[0]); mismatchedChunk.transportSha256="0".repeat(64); assert.throws(()=>authenticateCompleteRlsProbeObservation([...chunks.slice(1),JSON.stringify(mismatchedChunk),terminal],options)); assert.throws(()=>authenticateCompleteRlsProbeObservation([...chunks,forged],options)); });
test("bounded CloudWatch polling succeeds after delayed ingestion and times out without relaunch", async () => { const keys=createSecurityCatalogueTransportKeyPair(), binding={...probeIdentity,requirementsSha256:digest,securityMode:true}, chunks=encryptSecurityCatalogueTransport({padding:crypto.randomBytes(300000).toString("hex")},keys.publicKeyPem,{sourceSha,candidateSourceSha:sourceSha,requirementsSha256:digest}), first=JSON.parse(chunks[0]), body={schemaVersion:1,kind:"PRODUCTION_RLS_CATALOGUE_PROBE",...probeIdentity,requirementsSha256:digest,databaseRole:APP_ONLY_VERIFIER.databaseRole,catalogue:{routines:[],tables:[],policies:[],schemas:[],roles:[]},securityTransport:{transportSha256:first.transportSha256,count:first.count}}, terminal=JSON.stringify({...body,evidenceSha256:canonicalSha256(body)}); for (const snapshots of [[[chunks[0]],[...chunks],[...chunks,terminal]],[[...chunks],[...chunks,terminal]],[[terminal,...chunks.slice(0,-1)],[...chunks,terminal]]]) { let reads=0, waits=0; const result=await waitForCompleteRlsProbeObservation(async()=>snapshots[Math.min(reads++,snapshots.length-1)],binding,{attempts:5,wait:async(ms)=>{assert.equal(ms,5000);waits++;}}); assert.ok(result); assert.equal(reads,snapshots.length); assert.equal(waits,reads-1); } let reads=0, waits=0; assert.equal(await waitForCompleteRlsProbeObservation(async()=>{reads++;return [chunks[0]];},binding,{attempts:3,wait:async()=>{waits++;}}),null); assert.equal(reads,3); assert.equal(waits,2); });
test("private comparison writes mode 0600 and returns only bounded summary", () => { const directory=fs.mkdtempSync(path.join(os.tmpdir(),"rebaseline-test-")); try { const target=canonical(), observed=live(catalogue(),target), canonicalPath=path.join(directory,"canonical.json"),livePath=path.join(directory,"live.json"),outPath=path.join(directory,"diff.json"); writeStageBPrivateFileExclusive({filePath:canonicalPath,bytes:Buffer.from(JSON.stringify(target)),repositoryRoot:root}); writeStageBPrivateFileExclusive({filePath:livePath,bytes:Buffer.from(JSON.stringify(observed)),repositoryRoot:root}); const result=compareProductionSecurityRebaseline({sourceSha,livePath,canonicalPath,outPath,repositoryRoot:root,assertCheckout:()=>{}}); assert.equal(result.differenceCount,0); assert.equal(Object.hasOwn(result,"differences"),false); assert.equal(fs.statSync(outPath).mode&0o777,0o600); } finally { fs.rmSync(directory,{recursive:true,force:true}); } });
