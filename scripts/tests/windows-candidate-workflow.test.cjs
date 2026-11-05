const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');
const workflow = yaml.load(fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/windows-connector-signed-release.yml'), 'utf8'));

test('candidate signing requires protected environment and cannot publish release files', () => {
  const job = workflow.jobs['build-sign-windows'];
  assert.equal(job.environment, 'production-signing');
  assert.equal(job.permissions.contents, 'read', 'candidate token must not publish repository releases or commits');
  assert.equal(workflow.on.workflow_dispatch.inputs.execution_mode.default, 'build_verify_only');
  const blocker = job.steps.find(s => s.name === 'Block release while upgrade safety is incomplete');
  assert.equal(blocker.if, "github.event_name != 'workflow_dispatch' || inputs.execution_mode != 'build_verify_only'");
  assert.match(blocker.run, /throw /);
  assert(job.steps.indexOf(blocker) < job.steps.findIndex(s => s.name === 'Azure login'));
  const mutators = job.steps.filter(s => /git push|connector:windows:publish-signed/.test(s.run || ''));
  assert.equal(mutators.length, 2);
  for (const step of mutators) assert.match(step.if, /inputs.execution_mode == 'publish'/);
  const upload = job.steps.find(s => s.uses?.startsWith('actions/upload-artifact@'));
  assert.match(upload.with.name, /candidate/);
  assert(!upload.with.path.includes('manifest.json'));
  const prepare=job.steps.find(step=>step.name==='Prepare unsigned Windows installer scaffold');
  assert.equal(prepare.run,'npm --prefix backend run connector:windows:prepare-signed-candidate');
  assert.equal(prepare.env.MSCQR_APPROVED_MAINTENANCE_API_ORIGIN,'${{ vars.MSCQR_APPROVED_MAINTENANCE_API_ORIGIN }}','origin allowlist must come from protected configuration, not a dispatch input');
});
