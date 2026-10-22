import test from 'node:test';
import assert from 'node:assert/strict';
import {createBridgeCredentialRefresher} from '../aws/production-release-bridge-credentials.mjs';

const time=Date.parse('2026-10-22T01:00:00.000Z');
const env={GITHUB_ACTIONS:'true',GITHUB_RUN_ID:'123',ACTIONS_ID_TOKEN_REQUEST_URL:'https://token.actions.githubusercontent.com/request',
 ACTIONS_ID_TOKEN_REQUEST_TOKEN:'private',AWS_CREDENTIAL_EXPIRATION:new Date(time+15*60*1000).toISOString(),AWS_ACCESS_KEY_ID:'old'};
test('expired hosted session is renewed through the same exact OIDC role without exposing the token',async()=>{
 let calls=0;
 const refresh=createBridgeCredentialRefresher({env,now:()=>time,fetchImpl:async(url,options)=>{
  assert.equal(url.searchParams.get('audience'),'sts.amazonaws.com');assert.equal(options.headers.Authorization,'Bearer private');
  return {ok:true,json:async()=>({value:'x'.repeat(101)})};
 },assume:async token=>{calls++;assert.equal(token,'x'.repeat(101));return {Credentials:{AccessKeyId:'new',SecretAccessKey:'secret',SessionToken:'session',Expiration:new Date(time+3600000)}};}});
 assert.equal((await refresh.ensure()).AWS_ACCESS_KEY_ID,'new');
 assert.equal((await refresh.ensure()).AWS_ACCESS_KEY_ID,'new');
 assert.equal(calls,1);
});
test('missing OIDC endpoint or incomplete renewed credentials fails closed',async()=>{
 assert.throws(()=>createBridgeCredentialRefresher({env:{...env,ACTIONS_ID_TOKEN_REQUEST_TOKEN:''},now:()=>time}));
 const refresh=createBridgeCredentialRefresher({env,now:()=>time,fetchImpl:async()=>({ok:true,json:async()=>({value:'x'.repeat(101)})}),
  assume:async()=>({Credentials:{AccessKeyId:'new',SecretAccessKey:'secret',SessionToken:'session',Expiration:new Date(time+1000)}})});
 await assert.rejects(()=>refresh.ensure(),/too short/);
});
