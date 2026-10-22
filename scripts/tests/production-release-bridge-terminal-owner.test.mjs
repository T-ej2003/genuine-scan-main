import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {readTerminalOwner} from '../aws/production-release-bridge-terminal-owner.mjs';

test('same private terminal owner resumes one claimed authorization without creating a second identity',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-terminal-owner-'));
 try{
  const input={directory,operationId:'a'.repeat(64),requestSha256:'b'.repeat(64)};
  const first=readTerminalOwner(input),again=readTerminalOwner(input);
  assert.deepEqual(again,first);
  assert.notEqual(readTerminalOwner({...input,requestSha256:'c'.repeat(64)}).terminalId,first.terminalId);
  const file=path.join(directory,`.bridge-terminal-owner-${input.operationId}-${input.requestSha256}.json`);
  fs.chmodSync(file,0o644);
  assert.throws(()=>readTerminalOwner(input),/not private/);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
