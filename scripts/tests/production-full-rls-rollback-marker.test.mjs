import assert from 'node:assert/strict';
import test from 'node:test';
import {assertExactRollbackTarget} from '../../backend/scripts/full-rls-green-executor-core.mjs';
import {PRODUCTION_GREEN} from '../../backend/scripts/production-full-rls-green-executor.mjs';

const source='a'.repeat(64);
const bound={checksums:{sourceContractSha256:source}};
const url=new URL('postgresql://mscqr_prod_admin@mscqr-production-db.internal/mscqr_production?sslmode=require');

test('rollback checks the exact package marker and inactive database before DROP DATABASE',()=>{
 let sql;
 assertExactRollbackTarget(PRODUCTION_GREEN,url,bound,(target,statement,label)=>{
  assert.equal(target.pathname,`/${PRODUCTION_GREEN.database}`);
  assert.equal(label,'rollback-package-marker');sql=statement;return '1';
 });
 for(const text of [source,PRODUCTION_GREEN.deploymentId,'green_database=current_database()',
  "administrator_role=current_user","NOT traffic_enabled","mscqr_rls_install.state"])
  assert.ok(sql.includes(text));
 for(const result of ['0','2',''])assert.throws(()=>assertExactRollbackTarget(PRODUCTION_GREEN,url,bound,
  ()=>result),/unmarked, changed or active/);
});
