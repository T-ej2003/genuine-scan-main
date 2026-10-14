import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import os from "node:os";
import path from "node:path";
import {historicalRuntimeFixture} from "./fixtures/historical-runtime.mjs";
import yaml from "js-yaml";
import { assertNormalReleaseAuthorizationTransport, assertNormalReleaseGateInputs,packReleaseEvidenceTransport,unpackReleaseEvidenceTransport,runCli } from "../aws/production-release-dispatch-contract.mjs";
import { assertReleaseTrainNormalDispatchContract } from "../aws/production-release-oidc-contract.mjs";
import { verifyProductionReleaseImageAuthorization } from "../aws/verify-production-release-image-authorization.mjs";
import { verifyCoordinatedWebRelease } from "../aws/verify-production-web-release-authorization.mjs";
import { IMAGE_EVIDENCE_MAX_AGE_MS } from "../aws/production-green-stage-b-image-evidence.mjs";
import { WEB_RELEASE_DOWNSTREAM_RESERVE_MS } from "../aws/production-web-release-contract.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const fixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha });
const bytes = Buffer.from(JSON.stringify(fixture.authorization));
const digest = crypto.createHash("sha256").update(bytes).digest("hex");
const authenticate = (authorization, expectedSourceSha) => {
  verifyProductionReleaseImageAuthorization({ authorization, sourceSha: expectedSourceSha, verifyImageEvidence: fixture.verifyImageEvidence, now: fixture.now });
  return true;
};
const webAuthorization = { operation: "PRODUCTION_WEB_IMAGE_AUTHORIZATION", valid: true, sourceSha };
const webBytes = Buffer.from(JSON.stringify(webAuthorization));
const webDigest = crypto.createHash("sha256").update(webBytes).digest("hex");
const webImpactFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha, impactImageReleaseSha: "594bab55f23ff8b2438c12b85b149ba0aebeed1e" });
const webImpactBytes = Buffer.from(JSON.stringify(webImpactFixture.authorization));
const webImpactDigest = crypto.createHash("sha256").update(webImpactBytes).digest("hex");
const authenticateWebImpact = (authorization, expectedSourceSha) => {
  verifyProductionReleaseImageAuthorization({ authorization, sourceSha: expectedSourceSha, verifyImageEvidence: webImpactFixture.verifyImageEvidence, now: webImpactFixture.now });
  return true;
};

test("Release Train validates and forwards the complete normal Release Gate contract", () => {
  const releaseTrain = yaml.load(fs.readFileSync(".github/workflows/release-train.yml", "utf8"));
  assert.equal(assertReleaseTrainNormalDispatchContract(releaseTrain), true);
  const dispatch = releaseTrain.jobs.orchestrate.steps.find(({ name }) => name === "Trigger final Release Gate").run;
  assert.equal(spawnSync("bash", ["-n"], { input: dispatch, encoding: "utf8" }).status, 0);
  assert.equal(assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: bytes, expectedSha256: digest }).authenticationDeferredToReleaseGate, true);
  assert.equal(assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: true, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), true);
});

test("normal Release Gate rejects missing preservation, missing or stale authorization, and wrong source", () => {
  assert.throws(() => assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: false, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), /frontend action/);
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: Buffer.alloc(0), expectedSha256: digest }), /hash-mismatched/);
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: bytes, expectedSha256: "0".repeat(64) }), /hash-mismatched/);
  const stale = Buffer.from(JSON.stringify({ ...fixture.authorization, sourceSha: "b".repeat(40) }));
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: stale, expectedSha256: crypto.createHash("sha256").update(stale).digest("hex") }), /stale/);
  assert.throws(() => assertNormalReleaseGateInputs({ sourceSha: "b".repeat(40), preserveCurrentFrontend: true, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), /stale|source/);
});

test("normal Release Gate reserves Stage-B evidence lifetime before downstream mutation", () => {
  const now = new Date(Date.parse(fixture.now) + IMAGE_EVIDENCE_MAX_AGE_MS - WEB_RELEASE_DOWNSTREAM_RESERVE_MS + 1).toISOString();
  assert.throws(() => verifyProductionReleaseImageAuthorization({ authorization: fixture.authorization, sourceSha, verifyImageEvidence: fixture.verifyImageEvidence, now, minimumRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }), /remaining lifetime/);
  assert.doesNotThrow(() => verifyProductionReleaseImageAuthorization({ authorization: fixture.authorization, sourceSha, verifyImageEvidence: fixture.verifyImageEvidence, now: fixture.now, minimumRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }));
});

test("coordinated web verification reserves Stage-B evidence before crossing the database boundary", async () => {
  const now = new Date(Date.parse(fixture.now) + IMAGE_EVIDENCE_MAX_AGE_MS - WEB_RELEASE_DOWNSTREAM_RESERVE_MS + 1).toISOString();
  await assert.rejects(() => verifyCoordinatedWebRelease({ sourceSha, stageBAuthorization: fixture.authorization, verifyStageBImageEvidence: fixture.verifyImageEvidence, now, minimumWebAuthorizationRemainingMs: WEB_RELEASE_DOWNSTREAM_RESERVE_MS }), /remaining lifetime/);
});

test("web-impacting normal release requires source-bound web transport and activates instead of preserving", () => {
  assert.equal(assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: webImpactBytes, expectedSha256: webImpactDigest, webAuthorizationBytes: webBytes, webExpectedSha256: webDigest, webPublicationRequired: true }).webPublicationRequired, true);
  assert.equal(assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: false, authorizationBytes: webImpactBytes, expectedSha256: webImpactDigest, webAuthorizationBytes: webBytes, webExpectedSha256: webDigest, webPublicationRequired: true, authenticateAuthorization: authenticateWebImpact, authenticateWebAuthorization: (value, sha) => value === webAuthorization || value.sourceSha === sha }), true);
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: webImpactBytes, expectedSha256: webImpactDigest, webPublicationRequired: true }), /Web image-authorization|requires web/);
  assert.throws(() => assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: true, authorizationBytes: webImpactBytes, expectedSha256: webImpactDigest, webAuthorizationBytes: webBytes, webExpectedSha256: webDigest, webPublicationRequired: true, authenticateAuthorization: authenticateWebImpact, authenticateWebAuthorization: () => true }), /frontend action/);
  const tampered = structuredClone(webImpactFixture.authorization); tampered.imageReuseEvidence.webPublicationRequired = false;
  const tamperedBytes = Buffer.from(JSON.stringify(tampered));
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: tamperedBytes, expectedSha256: crypto.createHash("sha256").update(tamperedBytes).digest("hex"), webPublicationRequired: false }), /canonical source-bound envelope/);
});


test('existing release transport binds durable registration source and rejects malformed or substituted references',()=>{
 const authorizationJson=bytes.toString(),authorizationSha256=digest,completedRegistrationSourceSha='a'.repeat(40);
 const packed=packReleaseEvidenceTransport({authorizationJson,authorizationSha256,completedRegistrationSourceSha});
 const decoded=unpackReleaseEvidenceTransport(packed);
 assert.equal(decoded.completedRegistrationSourceSha,completedRegistrationSourceSha);
 assert.equal(decoded.authorizationJson,authorizationJson);assert.equal(decoded.authorizationSha256,digest);
 assert.deepEqual(packReleaseEvidenceTransport({authorizationJson:packed.json,authorizationSha256:packed.sha256}),packed);
 assert.throws(()=>packReleaseEvidenceTransport({authorizationJson:packed.json,authorizationSha256:packed.sha256,completedRegistrationSourceSha:'b'.repeat(40)}),/substitution/);
 const crossTicket=packReleaseEvidenceTransport({authorizationJson:packed.json,authorizationSha256:packed.sha256,completedRegistrationTicketId:'CHG-20261011-001'});
 assert.equal(unpackReleaseEvidenceTransport(crossTicket).completedRegistrationTicketId,'CHG-20261011-001');
 assert.deepEqual(packReleaseEvidenceTransport({authorizationJson:crossTicket.json,authorizationSha256:crossTicket.sha256}),crossTicket);
 assert.throws(()=>packReleaseEvidenceTransport({authorizationJson:crossTicket.json,authorizationSha256:crossTicket.sha256,completedRegistrationTicketId:'CHG20261013-001'}),/substitution/);
 assert.throws(()=>packReleaseEvidenceTransport({authorizationJson,authorizationSha256,completedRegistrationTicketId:'CHG-20261011-001'}),/requires an exact source/);
 for(const ticket of ['',null,{},'bad ticket'])assert.throws(()=>packReleaseEvidenceTransport({authorizationJson,authorizationSha256,completedRegistrationSourceSha,completedRegistrationTicketId:ticket}));
 const historicalRuntimeJson=JSON.stringify(historicalRuntimeFixture().evidence),historicalRuntimeSha256=crypto.createHash('sha256').update(historicalRuntimeJson).digest('hex');
 const combined=packReleaseEvidenceTransport({authorizationJson:packed.json,authorizationSha256:packed.sha256,historicalRuntimeJson,historicalRuntimeSha256});
 const combinedDecoded=unpackReleaseEvidenceTransport(combined);
 assert.equal(combinedDecoded.authorizationJson,authorizationJson);assert.equal(combinedDecoded.historicalRuntimeJson,historicalRuntimeJson);assert.equal(combinedDecoded.completedRegistrationSourceSha,completedRegistrationSourceSha);
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-durable-transport-test-'));
 try{const file=path.join(directory,'authorization.json');fs.writeFileSync(file,packed.json,{mode:0o600});
  assert.equal(runCli(['--source-sha',sourceSha,'--authorization',file,'--authorization-sha256',packed.sha256]).sourceSha,sourceSha);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}

 assert.deepEqual(packReleaseEvidenceTransport({authorizationJson,authorizationSha256}),{json:authorizationJson,sha256:digest});
 assert.throws(()=>unpackReleaseEvidenceTransport({...packed,json:packed.json.replace(completedRegistrationSourceSha,'b'.repeat(40))}),/checksum/);
 assert.throws(()=>unpackReleaseEvidenceTransport({...crossTicket,json:crossTicket.json.replace('CHG-20261011-001','CHG20261013-001')}),/checksum/);
 for(const reference of ['',null,{},'main','a'.repeat(39)])assert.throws(()=>packReleaseEvidenceTransport({authorizationJson,authorizationSha256,completedRegistrationSourceSha:reference}));
 for(const change of [v=>{delete v.completedRegistrationSourceSha;},v=>{v.extra=true;},v=>{v.schemaVersion=1;},v=>{v.completedRegistrationSourceSha='main';},v=>{v.imageAuthorizationSha256='0'.repeat(64);}]){
  const value=JSON.parse(packed.json);change(value);const json=JSON.stringify(value);
  assert.throws(()=>unpackReleaseEvidenceTransport({json,sha256:crypto.createHash('sha256').update(json).digest('hex')}));
 }
});
