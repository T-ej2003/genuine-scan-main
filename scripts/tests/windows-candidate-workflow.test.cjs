const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const yaml = require('js-yaml');
const workflow = yaml.load(fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/windows-connector-signed-release.yml'), 'utf8'));

test('candidate signing requires protected environment and cannot publish release files', () => {
  const job = workflow.jobs['build-sign-windows'];
  assert.equal(job.environment, 'production-signing');
  assert.equal(job.permissions.contents, 'read', 'installer execution must not receive a repository write token');
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

test('fresh-install publication reuses only the attested signed candidate after a real clean-host install', () => {
  const signer = workflow.jobs['build-sign-windows'];
  const job = workflow.jobs['fresh-install'];
  assert.match(signer.if, /inputs.execution_mode == 'build_verify_only'/);
  assert(!signer.if.includes('publish_fresh_install'));
  assert.equal(job.environment, 'production-signing');
  assert.match(job.if, /certify_fresh_install/);
  assert.match(job.if, /publish_fresh_install/);
  const source = job.steps.find(step => step.name === 'Authenticate and download the existing signed candidate').run;
  for (const required of ['refs/heads/main', '$env:GITHUB_SHA', 'INPUT_SIGNED_CANDIDATE_RUN_ID',
    'INPUT_SIGNED_INSTALLER_SHA256', 'gh attestation verify', 'Get-AuthenticodeSignature',
    'gh run download', 'git rev-parse HEAD']) assert(source.includes(required));
  assert.match(source, /\$run\.head_branch -cne 'main'/);
  assert.match(source, /\$run\.head_sha -cne \$source/);
  assert.match(source, /\$matching.Count -ne 1/);
  assert.match(source, /\$run\.workflow_id -ne 273963817/);
  assert.match(source, /\.digest\.sha256 -ceq \$expected/);
  const install = job.steps.find(step => step.name === 'Certify first installation without maintenance authorization').run;
  assert(!/\$home\b/i.test(install), 'PowerShell HOME is a read-only automatic variable');
  assert.match(install, /Start-Process.*-Wait -PassThru/);
  assert.match(install, /\/VERYSILENT/);
  assert.match(install, /\$setup[.]ExitCode/);
  assert.match(install, /install-result[.]json/);
  assert.match(install, /status[.]buildVersion/);
  assert(!install.includes('/MSCQRAUTH='));
  const publish = job.steps.find(step => step.name === 'Stage fresh-install-only release files for review');
  assert.equal(publish.if, "inputs.execution_mode == 'publish_fresh_install'");
  assert.equal(publish.env.WINDOWS_CONNECTOR_FRESH_INSTALL_ONLY, 'true');
  assert.match(publish.run, /refs\/heads\/main/);
  assert(!publish.run.includes('git push'));
  assert(job.steps.some(step => step.uses?.startsWith('actions/upload-artifact@') && step.if === "inputs.execution_mode == 'publish_fresh_install'"));
  assert(!job.steps.some(step => /azure login|sign staged|compile windows installer/i.test(step.name || '')));
});

test('signed source and a policy sibling share only the pinned parent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-connector-lineage-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', env: {
    ...process.env, GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.invalid',
    GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.invalid',
  } }).trim();
  try {
    git('init', '-q', '-b', 'base');
    fs.writeFileSync(path.join(dir, 'signed.txt'), 'base');
    git('add', 'signed.txt'); git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    git('switch', '-qc', 'signed');
    fs.writeFileSync(path.join(dir, 'signed.txt'), 'approved');
    git('commit', '-qam', 'signed');
    const source = git('rev-parse', 'HEAD');
    git('switch', '-qc', 'policy', base);
    fs.writeFileSync(path.join(dir, 'signed.txt'), 'approved');
    git('commit', '-qam', 'policy sibling');
    const accepts = () => git('rev-parse', `${source}^`) === base &&
      [source, base].includes(git('merge-base', source, 'HEAD')) &&
      git('diff', source, 'HEAD', '--', 'signed.txt') === '';
    assert(accepts(), 'legitimate sibling with identical signed source must pass');
    fs.writeFileSync(path.join(dir, 'signed.txt'), 'tampered');
    git('commit', '-qam', 'tamper');
    assert(!accepts(), 'changed installer source must fail');
    git('switch', '--orphan', 'unrelated');
    git('commit', '-qm', 'unrelated', '--allow-empty');
    assert.throws(() => git('merge-base', source, 'HEAD'), 'unrelated history must fail');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
