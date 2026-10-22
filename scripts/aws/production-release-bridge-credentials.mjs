import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

const requireBackend=createRequire(new URL('../../backend/package.json',import.meta.url));
const roleArn='arn:aws:iam::368992683803:role/mscqr-production-release-deployer';

export function createBridgeCredentialRefresher({env=process.env,fetchImpl=fetch,assume,now=Date.now}={}){
 assert.equal(env.GITHUB_ACTIONS,'true');assert.match(String(env.GITHUB_RUN_ID||''),/^[1-9][0-9]*$/);
 assert.ok(env.ACTIONS_ID_TOKEN_REQUEST_URL&&env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,'GitHub OIDC renewal endpoint is unavailable');
 let current={...env},expiresAt=Date.parse(env.AWS_CREDENTIAL_EXPIRATION);
 assert.ok(Number.isSafeInteger(expiresAt)&&expiresAt>now(),'Initial release-deployer session has no authenticated expiry');
 const assumeRole=assume||(async token=>{
  const {STSClient,AssumeRoleWithWebIdentityCommand}=requireBackend('@aws-sdk/client-sts');
  const client=new STSClient({region:'eu-west-2',credentials:undefined});
  try{return await client.send(new AssumeRoleWithWebIdentityCommand({RoleArn:roleArn,RoleSessionName:`release-bridge-${env.GITHUB_RUN_ID}`,
   WebIdentityToken:token,DurationSeconds:3600}));}
  finally{client.destroy();}
 });
 return {
  env:()=>current,
  async ensure({minimumRemainingMs=20*60*1000}={}){
   assert.ok(Number.isSafeInteger(minimumRemainingMs)&&minimumRemainingMs>=0&&minimumRemainingMs<=40*60*1000);
   if(expiresAt-now()>minimumRemainingMs)return current;
   const url=new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
   url.searchParams.set('audience','sts.amazonaws.com');
   const response=await fetchImpl(url,{headers:{Authorization:`Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`}});
   if(!response.ok)throw new Error('GitHub OIDC token renewal failed');
   const token=(await response.json()).value;
   assert.ok(typeof token==='string'&&token.length>100,'GitHub OIDC token is malformed');
   let session;
   try{session=await assumeRole(token);}catch{throw new Error('Exact release-deployer OIDC role renewal failed');}
   const credentials=session?.Credentials,nextExpiry=Date.parse(credentials?.Expiration);
   assert.ok(credentials?.AccessKeyId&&credentials.SecretAccessKey&&credentials.SessionToken&&nextExpiry-now()>minimumRemainingMs,
    'Renewed release-deployer session is incomplete or too short');
   current={...current,AWS_ACCESS_KEY_ID:credentials.AccessKeyId,AWS_SECRET_ACCESS_KEY:credentials.SecretAccessKey,
    AWS_SESSION_TOKEN:credentials.SessionToken,AWS_CREDENTIAL_EXPIRATION:new Date(nextExpiry).toISOString()};
   expiresAt=nextExpiry;
   return current;
  },
 };
}
