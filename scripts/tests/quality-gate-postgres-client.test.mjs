import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import yaml from 'js-yaml';

const workflow=yaml.load(fs.readFileSync('.github/workflows/quality-gate.yml','utf8'));

test('frontend and integration install PostgreSQL client from bounded signed Noble main indexes',()=>{
 for(const name of ['frontend','integration']){
  const steps=workflow.jobs[name].steps.filter(step=>step.name==='Install PostgreSQL client');
  assert.equal(steps.length,1);
  const [step]=steps;
  assert.equal(step['timeout-minutes'],5);
  assert.match(step.run,/Dir::Etc::sourcelist=.*mscqr-postgres-client\.list/);
  assert.match(step.run,/Dir::Etc::sourceparts=-/);
  assert.match(step.run,/noble-security main/);
  assert.doesNotMatch(step.run,/\buniverse\b|\bmultiverse\b/);
  assert.match(step.run,/install -y --no-install-recommends postgresql-client/);
  assert.match(step.run,/command -v psql[\s\S]*command -v pg_isready/);
 }
});
