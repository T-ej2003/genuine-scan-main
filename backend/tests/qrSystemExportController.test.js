const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

process.env.NODE_ENV = "test";
const distRoot=path.resolve(__dirname,"../dist");
const repositoryPath=require.resolve(path.join(distRoot,"rls-waves/session-c/c01/qrSystemRepository.js"));
const { visitQrCodePages }=require(repositoryPath);
let fail=false;
let audit=null;
const rows=Array.from({length:5},(_,index)=>({
  id:`qr-${index}`,code:`code-${index}`,displayCode:`D${index}`,status:"DORMANT",
  licensee:{name:"Licensee",prefix:"LIC"},batchId:null,batch:null,scanCount:0,createdAt:`2026-01-0${index+1}T00:00:00.000Z`,
}));
require.cache[repositoryPath]={
  id:repositoryPath,filename:repositoryPath,loaded:true,exports:{
    visitQrCodePages,
    withQrBoundaryTransaction:(fn)=>fn({}),
    readCodes:async (input)=>{
      if(fail && input.offset>0) return {qrCodes:[],total:rows.length};
      return {qrCodes:rows.slice(input.offset,input.offset+2),total:rows.length};
    },
    isQrBoundaryDenied:()=>false,
  },
};
const auditPath=require.resolve(path.join(distRoot,"services/auditService.js"));
require.cache[auditPath]={id:auditPath,filename:auditPath,loaded:true,exports:{createAuditLog:async (input)=>{audit=input;}}};

const response=()=>({
  statusCode:200,body:null,headers:{},sentFile:false,
  status(code){this.statusCode=code;return this;},
  json(body){this.body=body;return this;},
  setHeader(name,value){this.headers[name]=value;},
  sendFile(file,callback){this.sentFile=true;this.body=readFileSync(file,"utf8");callback();},
});
const request={
  user:{userId:"platform",role:"SUPER_ADMIN"},databaseSessionCapability:"C".repeat(43),
  requestId:"export-review",query:{},ip:"127.0.0.1",
};

(async()=>{
  const { exportQRCodesCsv }=require("../dist/controllers/qrController");
  const success=response();
  await exportQRCodesCsv(request,success);
  assert.equal(success.sentFile,true);
  assert.equal(success.body.trim().split("\n").length,6);
  assert.equal(audit.details.count,5);
  assert.deepEqual(success.body.match(/code-[0-4]/g),["code-0","code-1","code-2","code-3","code-4"]);

  fail=true;
  const incomplete=response();
  const originalError=console.error;
  console.error=()=>{};
  try {
    await exportQRCodesCsv(request,incomplete);
  } finally {
    console.error=originalError;
  }
  assert.equal(incomplete.sentFile,false);
  assert.equal(incomplete.statusCode,500);
  assert.equal(incomplete.body.success,false);
  console.log("QR export controller regression: PASS");
})().catch((error)=>{
  console.error(error);
  process.exitCode=1;
});
