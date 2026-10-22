import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

export function readTerminalOwner({directory,operationId,requestSha256}={}){
 assert.match(operationId||'',/^[a-f0-9]{64}$/);
 assert.match(requestSha256||'',/^[a-f0-9]{64}$/);
 const file=path.join(directory,`.bridge-terminal-owner-${operationId}-${requestSha256}.json`);
 let record;
 try{
  record={operationId,requestSha256,terminalId:randomBytes(32).toString('hex')};
  fs.writeFileSync(file,JSON.stringify(record),{flag:'wx',mode:0o600});
 }catch(error){if(error.code!=='EEXIST')throw error;}
 const stat=fs.lstatSync(file);
 assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o077)===0,'Terminal owner file is not private');
 const saved=JSON.parse(fs.readFileSync(file,'utf8'));
 assert.deepEqual(Object.keys(saved).sort(),['operationId','requestSha256','terminalId'].sort());
 assert.equal(saved.operationId,operationId);assert.equal(saved.requestSha256,requestSha256);
 assert.match(saved.terminalId||'',/^[a-f0-9]{64}$/);
 return saved;
}
