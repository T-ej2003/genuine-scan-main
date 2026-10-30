'use strict';
const assert = require('node:assert/strict'), crypto = require('node:crypto'), { gunzipSync, gzipSync } = require('node:zlib');
const session = require('./production-c02-session-executor.cjs');
const { canonicalJson, collectAppOnlyDatabaseCatalogueRows, hashProductionRlsCatalogue } = require('./production-printing-routine-delta-executor.cjs');
const hash = x => crypto.createHash('sha256').update(typeof x === 'string' ? x : canonicalJson(x)).digest('hex');
const names = ['printing_connector_event', 'printing_connector_identity', 'printing_create_job', 'printing_readiness', 'printing_reissue_request', 'printing_test_label_job'];
function validatePackage(pkg) {
    const { packageSha256, ...body } = pkg;
    assert.equal(packageSha256, hash(body));
    assert.equal(pkg.schemaVersion, 2);
    assert.equal(pkg.kind, 'PRODUCTION_C02_COMBINED_PREREQUISITE');
    assert.match(pkg.sourceSha, /^[a-f0-9]{40}$/);
    assert.equal(pkg.sessionPackage.sourceSha, pkg.sourceSha);
    assert.equal(pkg.sessionPackage.rolePrefix, 'mscqr_prd_rls_phase2_');
    const sessionBytes = Buffer.from(canonicalJson(pkg.sessionPackage));
    session.decodePackage(gzipSync(sessionBytes).toString('base64'), hash(sessionBytes.toString()));
    assert.deepEqual(pkg.definitions.map(definition => definition.name), names);
    for (const definition of pkg.definitions) {
        assert.ok(definition.sql.startsWith(`CREATE OR REPLACE FUNCTION app_rls.${definition.name}(`));
    }
    assert.equal(pkg.policySql.length, 6);
    assert.equal(pkg.migrationSql, 'ALTER TABLE "PrinterAgentSession"\n  ADD COLUMN "lastMessageSeq" INTEGER NOT NULL DEFAULT 0;');
    assert.equal(hash(pkg.migrationSql + '\n'), pkg.sessionPackage.migrationSha256);
    for (const digest of [pkg.predecessorRequirementsSha256, pkg.successorRequirementsSha256]) assert.match(digest, /^[a-f0-9]{64}$/);
    for (const catalogue of [pkg.predecessorCatalogue, pkg.successorCatalogue, pkg.finalCatalogue]) {
        assert.deepEqual(Object.keys(catalogue).sort(), ['policies', 'roles', 'routines', 'schemas', 'tables']);
        for (const digest of Object.values(catalogue)) assert.match(digest, /^[a-f0-9]{64}$/);
    }
    return pkg;
}

async function catalogueDigest(tx, collect = collectAppOnlyDatabaseCatalogueRows) {
    const rows = await collect(tx, identity => {
        assert.equal(identity.role, 'mscqr_prod_admin');
        assert.equal(identity.session_role, 'mscqr_prod_admin');
        assert.equal(identity.database, 'mscqr_production_rls_green_phase2');
        assert.equal(identity.rolsuper, false);
        assert.equal(identity.rolbypassrls, false);
    });
    return Object.fromEntries(Object.entries(hashProductionRlsCatalogue(rows)).map(([key, value]) => [key, hash(value)]));
}

async function verifyCommittedCatalogue({ client, pkg }) {
    return client.$transaction(async tx => {
        await tx.$executeRawUnsafe('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
        const actual = await catalogueDigest(tx);
        assert.ok([pkg.successorCatalogue, pkg.finalCatalogue].some(expected => canonicalJson(actual) === canonicalJson(expected)),
            'Committed C02 catalogue differs');
        assert.equal(await migrationState(tx, pkg), true);
        return actual;
    }, { maxWait: 10000, timeout: 30000 });
}

const migrationName = '20261028210000_printer_agent_session_sequence';
async function migrationState(tx, pkg) {
    await tx.$executeRawUnsafe('SET LOCAL ROLE mscqr_prd_rls_phase2_migration');
    const rows = await tx.$queryRawUnsafe('SELECT checksum,finished_at,rolled_back_at FROM public."_prisma_migrations" WHERE migration_name=$1', migrationName);
    await tx.$executeRawUnsafe('RESET ROLE');
    assert.ok(rows.length <= 1, 'Ambiguous migration history');
    if (rows.length) {
        assert.equal(rows[0].checksum, pkg.sessionPackage.migrationSha256);
        assert.ok(rows[0].finished_at && !rows[0].rolled_back_at, 'Migration history is not committed');
    }
    return rows.length === 1;
}
async function recordMigration({ client, url, pkg, cli = '/app/node_modules/prisma/build/index.js' }) {
    const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), { execFileSync } = require('node:child_process');
    if (await client.$transaction(tx => migrationState(tx, pkg)))
        return;
    // Reconcile a committed DDL transaction through Prisma, never by fabricating history rows.
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-c02-migration-'));
    fs.chmodSync(d, 0o700);
    try {
        fs.mkdirSync(path.join(d, 'migrations', migrationName), { recursive: true });
        fs.writeFileSync(path.join(d, 'schema.prisma'), 'datasource db {\n provider = "postgresql"\n url = env("DATABASE_URL")\n}\n', { mode: 0o600 });
        fs.writeFileSync(path.join(d, 'migrations', migrationName, 'migration.sql'), pkg.migrationSql + '\n', { mode: 0o600 });
        const u = new URL(url);
        u.searchParams.set('options', '-c role=mscqr_prd_rls_phase2_migration');
        execFileSync(process.execPath, [cli, 'migrate', 'resolve', '--applied', migrationName, '--schema', path.join(d, 'schema.prisma')], { cwd: d, env: { PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: u.toString() }, timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
        assert.ok(await client.$transaction(tx => migrationState(tx, pkg)), 'Migration history verification failed');
    }
    finally {
        fs.rmSync(d, { recursive: true, force: true });
    }
}
async function executeC02CombinedTransaction({ tx, pkg, checkpoint = async () => { }, collect = collectAppOnlyDatabaseCatalogueRows }) {
    validatePackage(pkg);
    let converged = false;
    const digest = () => catalogueDigest(tx, collect);
    const base = await session.executeC02SessionInstallTransaction({ tx, pkg: pkg.sessionPackage, checkpoint, initialize: async () => {
            const recorded = await migrationState(tx, pkg);
            const before = await digest();
            if ([pkg.successorCatalogue, pkg.finalCatalogue].some(c => canonicalJson(before) === canonicalJson(c))) {
                converged = true;
                return;
            }
            assert.equal(canonicalJson(before), canonicalJson(pkg.predecessorCatalogue), 'Unknown combined C02 predecessor');
            assert.equal(recorded, false, 'Migration history contradicts predecessor schema');
            await tx.$executeRawUnsafe('SET LOCAL ROLE mscqr_prd_rls_phase2_owner');
            await tx.$executeRawUnsafe('SET LOCAL search_path=pg_catalog,public');
            await tx.$executeRawUnsafe(pkg.migrationSql);
            await tx.$executeRawUnsafe('RESET ROLE');
            await checkpoint('after-column-migration');
        } });
    if (converged)
        return { status: 'ALREADY_CONVERGED', writeCount: 0 };
    await tx.$executeRawUnsafe('SET LOCAL ROLE mscqr_prd_rls_phase2_owner');
    await tx.$executeRawUnsafe('GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner');
    await tx.$executeRawUnsafe('RESET ROLE');
    await tx.$executeRawUnsafe('SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner');
    for (const d of pkg.definitions) {
        await tx.$executeRawUnsafe(d.sql);
        await checkpoint('after-' + d.name);
    }
    await tx.$executeRawUnsafe('RESET ROLE');
    await tx.$executeRawUnsafe('SET LOCAL ROLE mscqr_prd_rls_phase2_owner');
    await tx.$executeRawUnsafe('REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner');
    for (const sql of pkg.policySql)
        await tx.$executeRawUnsafe(sql);
    await tx.$executeRawUnsafe('RESET ROLE');
    await checkpoint('before-combined-verification');
    assert.equal(canonicalJson(await digest()), canonicalJson(pkg.successorCatalogue), 'Combined C02 successor mismatch');
    return { status: 'APPLIED', writeCount: base.writeCount + 13 };
}
async function main() {
    let client;
    try {
        assert.equal(process.argv.length, 4);
        const [encoded, expected, host] = process.argv.slice(1);
        assert.match(host, /^[a-z0-9.-]+$/);
        assert.match(encoded, /^[A-Za-z0-9+/=]+$/);
        assert.ok(encoded.length <= 32768);
        const bytes = gunzipSync(Buffer.from(encoded, 'base64'), { maxOutputLength: 192 * 1024 });
        assert.equal(hash(bytes.toString()), expected);
        assert.equal(canonicalJson(JSON.parse(bytes)), bytes.toString());
        const pkg = validatePackage(JSON.parse(bytes));
        assert.equal(hash(pkg.migrationSql + '\n'), pkg.sessionPackage.migrationSha256);
        assert.ok(require('node:fs').existsSync('/app/node_modules/prisma/build/index.js'));
        assert.equal(pkg.sourceSha, process.env.RELEASE_GIT_SHA);
        assert.ok(process.env.MSCQR_C02_ADMIN_PASSWORD);
        const u = new URL('postgresql://mscqr_prod_admin@' + host + ':5432/mscqr_production_rls_green_phase2?sslmode=require');
        u.password = process.env.MSCQR_C02_ADMIN_PASSWORD;
        const { PrismaClient } = require('@prisma/client');
        client = new PrismaClient({ datasources: { db: { url: u.toString() } }, log: [] });
        const result = await client.$transaction(tx => executeC02CombinedTransaction({ tx, pkg }), { maxWait: 10000, timeout: 180000 });
        await recordMigration({ client, url: u.toString(), pkg });
        await verifyCommittedCatalogue({ client, pkg });
        const body = { schemaVersion: 2, kind: 'PRODUCTION_C02_COMBINED_INSTALL_RESULT', sourceSha: pkg.sourceSha, packageSha256: pkg.packageSha256, database: 'mscqr_production_rls_green_phase2', databaseRole: 'mscqr_prod_admin', ...result };
        process.stdout.write(JSON.stringify({ ...body, evidenceSha256: hash(body) }) + '\n');
    }
    catch {
        process.stderr.write('{"status":"blocked","reason":"c02-combined-failed-closed"}\n');
        process.exitCode = 1;
    }
    finally {
        if (client) await client.$disconnect();
    }
}
if (require.main === module)
    main();
module.exports = { executeC02CombinedTransaction, validatePackage, recordMigration, migrationState, verifyCommittedCatalogue, main };
