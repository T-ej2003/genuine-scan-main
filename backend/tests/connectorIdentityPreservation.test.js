const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-identity-test-'));
  const stateFile = path.join(root, 'state.json');
  process.env.PRINT_AGENT_STATE_FILE = stateFile;
  const { loadAgentState, saveAgentState } = require('../dist/local-print-agent/state');
  try {
    const first = await loadAgentState();
    first.selectedPrinterId = 'synthetic-printer';
    first.calibrationProfiles = { 'synthetic-printer': { dpi: 300, offsetXmm: 1 } };
    first.unknownRecovery = { uncertainJob: 'synthetic-do-not-replay' };
    await saveAgentState(first);
    const restored = await loadAgentState();
    for (const key of ['agentId', 'deviceFingerprint', 'publicKeyPem', 'privateKeyPem', 'selectedPrinterId']) {
      assert.equal(restored[key], first[key], `preserved field ${key}`);
    }
    assert.equal(restored.calibrationProfiles['synthetic-printer'].dpi, 300);
    assert.deepEqual(restored.unknownRecovery, first.unknownRecovery);
    const {spawnSync}=require('node:child_process');
    const validate=()=>spawnSync(process.execPath,[path.resolve(__dirname,'../dist/local-print-agent/index.js'),'--validate-state'],{
      encoding:'utf8',env:{...process.env,PRINT_AGENT_STATE_FILE:stateFile,PRINT_AGENT_LOCK_DIR:path.join(root,'lock')}});
    const beforeValidation=await fs.readFile(stateFile,'utf8');
    const validation=validate();
    assert.equal(validation.status,0,validation.stderr);
    assert.equal(JSON.parse(validation.stdout).agentId,first.agentId);
    assert.equal(await fs.readFile(stateFile,'utf8'),beforeValidation,'validation must not save or migrate state');
    await assert.rejects(fs.stat(path.join(root,'lock')),'validation must not compete with an installed runtime');
    const legacyRoot=path.join(root,'legacy-profile');
    const legacy=path.join(legacyRoot,'.authenticqr','local-print-agent-state.json');
    await fs.mkdir(path.dirname(legacy),{recursive:true});
    await fs.writeFile(legacy,beforeValidation);
    const legacyRun=spawnSync(process.execPath,['-e',`(async()=>{const s=require('./dist/local-print-agent/state');const v=await s.loadAgentState({initialize:false});await s.saveAgentState({...v});console.log(JSON.stringify(await s.inspectAgentState()));})().catch(()=>process.exitCode=1)`],{
      cwd:path.resolve(__dirname,'..'),encoding:'utf8',env:{...process.env,PRINT_AGENT_STATE_FILE:'',USERPROFILE:legacyRoot,HOME:legacyRoot}});
    assert.equal(legacyRun.status,0,legacyRun.stderr);
    assert.equal(JSON.parse(legacyRun.stdout).statePath,legacy);
    assert.equal(JSON.parse(await fs.readFile(legacy,'utf8')).privateKeyPem,first.privateKeyPem);
    await assert.rejects(fs.stat(path.join(legacyRoot,'.mscqr','local-print-agent-state.json')),'legacy persistence must not silently create a second identity location');
    const mismatched = { ...first, publicKeyPem: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString() };
    for (const bad of ['{interrupted', JSON.stringify({ agentId: first.agentId }), JSON.stringify(mismatched)]) {
      await fs.writeFile(stateFile, bad);
      await assert.rejects(loadAgentState());
      assert.equal(await fs.readFile(stateFile, 'utf8'), bad, 'unreadable identity must never be overwritten');
    }
    await fs.writeFile(stateFile,'{"privateKeyPem":"synthetic-sensitive-key-fragment');
    await assert.rejects(loadAgentState(),error=>!error.message.includes('synthetic-sensitive-key-fragment'),'malformed private JSON must not appear in an error');
    await fs.rm(stateFile);
    assert.notEqual(validate().status,0,'missing state must fail read-only validation');
    await assert.rejects(fs.stat(stateFile),'validation must not initialize a replacement identity');
    await fs.mkdir(stateFile);
    await assert.rejects(loadAgentState());
    assert((await fs.stat(stateFile)).isDirectory(), 'I/O errors must not replace state');
    console.log('Connector identity preservation tests passed');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
