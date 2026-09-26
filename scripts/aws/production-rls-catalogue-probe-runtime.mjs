import assert from "node:assert/strict";
import fs from "node:fs";
import { PrismaClient } from "@prisma/client";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { collectAppOnlyDatabaseCatalogue } from "./production-app-only-database-verifier.mjs";
import { encryptSecurityCatalogueTransport } from "./production-security-rebaseline-transport.mjs";
import { assertProductionRlsProbeImageSource, parseProductionRlsProbeRuntimeConfig } from "./production-rls-catalogue-probe-config.mjs";

const COLLECTIONS = Object.freeze(["routines", "tables", "policies", "schemas", "roles"]);
const ROLE = "mscqr_prod_rls_canary_read";
const DATABASE = "/mscqr_production_rls_green_phase2";
const APPLICATION = "mscqr-production-green-read-only-rls-canary";
const requirementIdentity = (collection, row) => collection === "routines" ? `${row.schema}.${row.name}(${row.arguments})`
  : collection === "policies" ? `${row.table}.${row.name}` : row.name;
const hashCatalogue = (catalogue) => Object.fromEntries(COLLECTIONS.map((name) => [name, catalogue[name]
  .map((row) => ({ identity: requirementIdentity(name, row), sha256: canonicalSha256(row) }))
  .sort((a, b) => a.identity.localeCompare(b.identity))]));

export async function runProductionRlsCatalogueProbe({ env = process.env, write = (line) => process.stdout.write(`${line}\n`), createClient = (url) => new PrismaClient({ datasources: { db: { url } } }) } = {}) {
  let client;
  try {
    const input = parseProductionRlsProbeRuntimeConfig(env.RLS_PROBE_INPUT_JSON);
    assertProductionRlsProbeImageSource(fs.readFileSync("/app/image-source.json", "utf8"), input.sourceSha);
    const url = new URL(String(env.RLS_CANARY_DATABASE_URL || ""));
    assert.match(url.protocol, /^postgres(?:ql)?:$/);
    assert.equal(url.username, ROLE);
    assert.equal(url.hostname, input.databaseHostname);
    assert.equal(url.pathname, DATABASE);
    assert.equal(url.searchParams.size, 2);
    assert.equal(url.searchParams.get("sslmode"), "require");
    assert.equal(url.searchParams.get("application_name"), APPLICATION);
    assert.equal(url.hash, "");
    client = createClient(url.toString());
    const catalogue = await collectAppOnlyDatabaseCatalogue(client);
    let securityTransport = null;
    if (input.securityTransportPublicKey) {
      const chunks = encryptSecurityCatalogueTransport(catalogue, input.securityTransportPublicKey,
        { sourceSha: input.sourceSha, candidateSourceSha: input.candidateSourceSha, requirementsSha256: input.requirementsSha256 });
      const first = JSON.parse(chunks[0]);
      securityTransport = { transportSha256: first.transportSha256, count: first.count };
      for (const chunk of chunks) write(chunk);
    }
    const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha: input.sourceSha, candidateSourceSha: input.candidateSourceSha,
      requirementsSha256: input.requirementsSha256, databaseRole: catalogue.identity.role,
      catalogue: hashCatalogue(catalogue), ...(securityTransport ? { securityTransport } : {}) };
    const output = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
    assert.ok(Buffer.byteLength(output) <= 196608);
    write(output);
    return 0;
  } catch {
    write(JSON.stringify({ status: "PRODUCTION_RLS_CATALOGUE_PROBE_FAILED" }));
    return 1;
  } finally {
    await client?.$disconnect().catch(() => {});
  }
}

if (process.argv[1]?.endsWith("production-rls-catalogue-probe-runtime.mjs")) {
  runProductionRlsCatalogueProbe().then((code) => { process.exitCode = code; });
}
