import test from 'node:test';
import assert from 'node:assert/strict';
import {terminalLockCommand} from '../aws/run-production-release-terminal-bridge.mjs';

test('trusted terminal uses the native nonblocking lock on Linux and macOS',()=>{
 const input={manifest:'/tmp/release.json',executable:'/usr/bin/node',script:'bridge.mjs',args:['--release-id','abc']};
 assert.deepEqual(terminalLockCommand({...input,platform:'linux'}),{
  command:'flock',args:['-n','/tmp/release.json.lock','/usr/bin/node','bridge.mjs','--release-id','abc']});
 assert.deepEqual(terminalLockCommand({...input,platform:'darwin'}),{
  command:'lockf',args:['-t','0','/tmp/release.json.lock','/usr/bin/node','bridge.mjs','--release-id','abc']});
 assert.throws(()=>terminalLockCommand({...input,platform:'win32'}),/Unsupported trusted-terminal lock platform/);
});
