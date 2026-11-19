const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-maintenance-'));
const stateFile = path.join(directory, 'local-print-agent-state.json');
process.env.PRINT_AGENT_STATE_FILE = stateFile;
const modulePath = require.resolve('../dist/local-print-agent/maintenanceFence');
const fence = require(modulePath);

(async () => {
  try {
    assert.deepEqual(fence.maintenanceCheckpoint(), { fenced: false, active: 0, idle: true });
    let finish;
    const ongoing = fence.runUnfencedWork(() => new Promise(resolve => { finish = resolve; }));
    assert.equal(fence.maintenanceCheckpoint().active, 1);
    assert.deepEqual(fence.enterMaintenanceFence(), { fenced: true, active: 1, idle: false });
    assert.equal(fs.statSync(path.join(directory, 'maintenance-fence.json')).mode & 0o777, 0o600);
    await assert.rejects(fence.runUnfencedWork(async () => { throw Error('work ran'); }), { errorCode: 'maintenance_fenced' });
    finish();
    await ongoing;
    assert.deepEqual(fence.maintenanceCheckpoint(), { fenced: true, active: 0, idle: true });
    const restarted = spawnSync(process.execPath, ['-e', `const f=require(${JSON.stringify(modulePath)}); process.exit(f.maintenanceFenced()?0:1)`],
      { env: { ...process.env, PRINT_AGENT_STATE_FILE: stateFile } });
    assert.equal(restarted.status, 0, 'restart must keep acquisition fenced');
    const { runGatewayCycle } = require('../dist/local-print-agent/gateway');
    await assert.rejects(runGatewayCycle('NETWORK_DIRECT'), { errorCode: 'maintenance_fenced' });
    assert.equal(fence.enterMaintenanceFence().fenced, true, 'repeated fencing is idempotent');
    fs.writeFileSync(path.join(directory, 'maintenance-fence.json'), '{interrupted');
    const corruptRestart = spawnSync(process.execPath, ['-e', `const f=require(${JSON.stringify(modulePath)}); process.exit(f.maintenanceFenced()?0:1)`],
      { env: { ...process.env, PRINT_AGENT_STATE_FILE: stateFile } });
    assert.equal(corruptRestart.status, 0, 'damaged marker must also prevent restart dispatch');
    console.log('connector maintenance fence tests passed');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
