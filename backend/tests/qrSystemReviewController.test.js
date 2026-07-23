const assert = require("node:assert/strict");
const path = require("node:path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";
const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let captured;
mockModule("rls-waves/session-c/c01/qrSystemRepository.js", {
  readInventoryProjection: async (input) => {
    captured = input;
    return {
      total: 3,
      rows: [
        { batchId:"empty",name:"Empty",licenseeId:"licensee-a",startCode:"A1",endCode:"A0",totalCodes:0,createdAt:"2026-01-03T00:00:00.000Z" },
        { batchId:"full",name:"Full",licenseeId:"licensee-a",startCode:"A1",endCode:"A2",totalCodes:2,createdAt:"2026-01-02T00:00:00.000Z",status:"DORMANT",count:2 },
      ],
    };
  },
});
mockModule("services/manufacturerScopeService.js", {
  resolveScopedLicenseeAccess: async () => ({ scopeLicenseeId:"licensee-a" }),
});

const response = () => ({
  statusCode:200,
  body:null,
  status(code){this.statusCode=code;return this;},
  json(body){this.body=body;return this;},
});

(async () => {
  const { getBatchSummary } = require("../dist/controllers/qrLogController");
  const res=response();
  await getBatchSummary({
    user:{userId:"tenant-admin",role:UserRole.LICENSEE_ADMIN},
    databaseSessionCapability:"C".repeat(43),
    requestId:"review-summary",
    query:{limit:"2",offset:"1"},
    get:()=>"",
  },res);
  assert.equal(res.statusCode,200);
  assert.deepEqual(res.body.meta,{total:3,limit:2,offset:1});
  assert.deepEqual(res.body.data[0].counts,{});
  assert.deepEqual(res.body.data[1].counts,{DORMANT:2});
  assert.equal(captured.limit,2);
  assert.equal(captured.offset,1);
  assert.equal(captured.licenseeId,"licensee-a");

  const { requireAdministrationMutator } = require("../dist/middleware/rbac");
  for (const role of [UserRole.SUPER_ADMIN,UserRole.PLATFORM_SUPER_ADMIN,UserRole.LICENSEE_ADMIN]) {
    let admitted=false;
    requireAdministrationMutator({user:{role}},response(),()=>{admitted=true;});
    assert.equal(admitted,true);
  }
  for (const role of [UserRole.MANUFACTURER_ADMIN,UserRole.ORG_ADMIN,UserRole.MANUFACTURER,UserRole.MANUFACTURER_USER]) {
    const denied=response();
    requireAdministrationMutator({user:{role}},denied,()=>assert.fail(`${role} must not reach QR deletion`));
    assert.equal(denied.statusCode,403);
  }

  const { bulkDeleteQRCodes } = require("../dist/controllers/qrController");
  const manufacturerDelete=response();
  await bulkDeleteQRCodes({
    user:{userId:"manufacturer-admin",role:UserRole.MANUFACTURER_ADMIN},
    databaseSessionCapability:"M".repeat(43),
    requestId:"manufacturer-delete",
    body:{ids:["40000000-0000-4000-8000-000000000506"]},
  },manufacturerDelete);
  assert.equal(manufacturerDelete.statusCode,403);
  console.log("QR system review controller regression: PASS");
})().catch((error)=>{
  console.error(error);
  process.exitCode=1;
});
