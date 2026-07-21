const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { CONFIRMATION_PHRASE,readConfig } = require("../scripts/seed-staging-rls-validation-data");

const valid = {
  STAGING_RLS_SEED_ENABLED:"true",
  STAGING_RLS_SEED_CONFIRM:CONFIRMATION_PHRASE,
  STAGING_RLS_SEED_ENVIRONMENT:"staging",
  STAGING_RLS_SEED_OPERATOR_ID:"00000000-0000-4400-8000-000000000001",
  STAGING_RLS_SEED_APPROVAL_ID:"00000000-0000-4400-8000-000000000044",
  DATABASE_URL:"postgresql://operator@127.0.0.1:55434/mscqr_rls_wave_c_admin_governance_operator",
};
assert.equal(readConfig(valid).environment,"staging");
assert.throws(()=>readConfig({...valid,STAGING_RLS_SEED_ENABLED:""}),/ENABLED=true/);
assert.throws(()=>readConfig({...valid,STAGING_RLS_SEED_CONFIRM:"wrong"}),/CONFIRM/);
assert.throws(()=>readConfig({...valid,DATABASE_URL:"postgresql://u@mscqr-prod-db/production"}),/production-looking/);

const run=spawnSync(process.execPath,[path.resolve(__dirname,"../scripts/seed-staging-rls-validation-data.js")],{encoding:"utf8",env:{PATH:process.env.PATH,DATABASE_URL:valid.DATABASE_URL}});
assert.equal(run.status,1);
const output=JSON.parse(run.stdout);
assert.equal(output.ok,false);
assert.equal(output.databaseUrlPrinted,false);
assert.doesNotMatch(run.stdout,/postgresql?:\/\//i);
console.log("staging RLS validation operator-boundary tests passed");
