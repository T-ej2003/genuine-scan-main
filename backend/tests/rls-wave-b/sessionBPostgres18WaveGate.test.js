const assert = require("node:assert/strict");

const enabled = process.env.MSCQR_RLS_WAVE_B_POSTGRES_TEST === "true";
const confirmed = process.env.MSCQR_RLS_WAVE_B_CONFIRM === "MSCQR_RUN_LOCAL_SESSION_B_WAVE_GATE";
const expectedDatabase = "mscqr_rls_wave_b_auth_public_workers";

const assertSafeUrl = (raw) => {
  const parsed = new URL(String(raw || ""));
  assert(["postgres:", "postgresql:"].includes(parsed.protocol), "Session B gate requires PostgreSQL");
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname), "Session B gate requires loopback PostgreSQL");
  assert.equal(decodeURIComponent(parsed.pathname.slice(1)), expectedDatabase, "Session B gate requires its exact database namespace");
  assert(!/(prod|production|staging|amazonaws|rds)/i.test(raw), "Session B gate refuses staging or production targets");
};

const expectRejected = async (operation, pattern) => {
  let error;
  try {
    await operation();
  } catch (caught) {
    error = caught;
  }
  assert(error, `Expected rejection matching ${pattern}`);
  assert.match(String(error.message || error), pattern);
};

const installProbe = async (prisma) => {
  await prisma.$executeRawUnsafe(`
    DO $roles$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_wave_b_authenticated') THEN
        CREATE ROLE mscqr_wave_b_authenticated NOLOGIN NOBYPASSRLS NOINHERIT;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_wave_b_public') THEN
        CREATE ROLE mscqr_wave_b_public NOLOGIN NOBYPASSRLS NOINHERIT;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_wave_b_worker') THEN
        CREATE ROLE mscqr_wave_b_worker NOLOGIN NOBYPASSRLS NOINHERIT;
      END IF;
    END
    $roles$;

    DROP SCHEMA IF EXISTS session_b_wave CASCADE;
    CREATE SCHEMA session_b_wave;

    CREATE TABLE session_b_wave.actor_record (
      id text PRIMARY KEY,
      user_id text NOT NULL,
      licensee_id text NOT NULL,
      payload text NOT NULL
    );
    CREATE TABLE session_b_wave.public_record (
      id text PRIMARY KEY,
      proof_hash text NOT NULL,
      payload text NOT NULL
    );
    CREATE TABLE session_b_wave.worker_job (
      id text PRIMARY KEY,
      status text NOT NULL CHECK (status IN ('QUEUED', 'CLAIMED')),
      payload_digest text NOT NULL,
      request_id uuid NOT NULL
    );

    INSERT INTO session_b_wave.actor_record VALUES
      ('actor-own', 'actor-a', 'licensee-a', 'own'),
      ('actor-foreign', 'actor-b', 'licensee-b', 'foreign');
    INSERT INTO session_b_wave.public_record VALUES
      ('public-a', repeat('a', 64), 'safe-public-projection');
    INSERT INTO session_b_wave.worker_job VALUES
      ('worker-job-a', 'QUEUED', repeat('b', 64), '174d1fe7-f82e-42a7-829a-ddb8ecf329cb');

    ALTER TABLE session_b_wave.actor_record ENABLE ROW LEVEL SECURITY;
    ALTER TABLE session_b_wave.actor_record FORCE ROW LEVEL SECURITY;
    ALTER TABLE session_b_wave.worker_job ENABLE ROW LEVEL SECURITY;
    ALTER TABLE session_b_wave.worker_job FORCE ROW LEVEL SECURITY;

    GRANT USAGE ON SCHEMA session_b_wave TO mscqr_wave_b_authenticated, mscqr_wave_b_public, mscqr_wave_b_worker;
    GRANT SELECT ON session_b_wave.actor_record TO mscqr_wave_b_authenticated;
    GRANT SELECT, UPDATE ON session_b_wave.worker_job TO mscqr_wave_b_worker;

    CREATE POLICY actor_record_self_scope ON session_b_wave.actor_record
      FOR SELECT TO mscqr_wave_b_authenticated
      USING (
        current_setting('app.user_id', true) = user_id
        AND current_setting('app.licensee_id', true) = licensee_id
        AND current_setting('app.auth_assurance', true) IN ('password-verified', 'mfa-verified', 'step-up-verified')
      );

    CREATE POLICY worker_job_select ON session_b_wave.worker_job
      FOR SELECT TO mscqr_wave_b_worker
      USING (
        current_setting('app.system_identity', true) = 'identity-worker'
        AND current_setting('app.job_id', true) = id
        AND current_setting('app.auth_assurance', true) = 'system-verified'
      );
    CREATE POLICY worker_job_update ON session_b_wave.worker_job
      FOR UPDATE TO mscqr_wave_b_worker
      USING (
        current_setting('app.system_identity', true) = 'identity-worker'
        AND current_setting('app.job_id', true) = id
        AND current_setting('app.auth_assurance', true) = 'system-verified'
      )
      WITH CHECK (
        current_setting('app.system_identity', true) = 'identity-worker'
        AND current_setting('app.job_id', true) = id
        AND current_setting('app.auth_assurance', true) = 'system-verified'
      );

    CREATE FUNCTION session_b_wave.read_public_record(requested_id text, supplied_proof_hash text)
      RETURNS TABLE(id text, payload text)
      LANGUAGE sql
      SECURITY DEFINER
      STABLE
      SET search_path = pg_catalog
      AS $fn$
        SELECT record.id, record.payload
        FROM session_b_wave.public_record AS record
        WHERE record.id = requested_id
          AND record.proof_hash = supplied_proof_hash
        LIMIT 1
      $fn$;
    REVOKE ALL ON FUNCTION session_b_wave.read_public_record(text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION session_b_wave.read_public_record(text, text) TO mscqr_wave_b_public;
  `);
};

const setActorContext = (tx, userId, licenseeId) => tx.$executeRaw`
  SELECT
    set_config('app.user_id', ${userId}, true),
    set_config('app.licensee_id', ${licenseeId}, true),
    set_config('app.auth_assurance', 'password-verified', true)
`;

const setWorkerContext = (tx, jobId) => tx.$executeRaw`
  SELECT
    set_config('app.system_identity', 'identity-worker', true),
    set_config('app.job_id', ${jobId}, true),
    set_config('app.auth_assurance', 'system-verified', true),
    set_config('app.user_id', '', true),
    set_config('app.role', '', true)
`;

const claimJob = (client) => client.$transaction(async (tx) => {
  await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_worker");
  await setWorkerContext(tx, "worker-job-a");
  return tx.$queryRaw`
    UPDATE session_b_wave.worker_job
    SET status = 'CLAIMED'
    WHERE id = 'worker-job-a' AND status = 'QUEUED'
    RETURNING id
  `;
});

const main = async () => {
  if (!enabled) {
    console.log("Session B PostgreSQL 18 wave gate skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_RLS_WAVE_B_CONFIRM=MSCQR_RUN_LOCAL_SESSION_B_WAVE_GATE");
  const databaseUrl = String(process.env.DATABASE_URL || "").trim();
  assertSafeUrl(databaseUrl);

  const { PrismaClient } = require("@prisma/client");
  const admin = new PrismaClient();
  const connectionA = new PrismaClient();
  const connectionB = new PrismaClient();
  try {
    const [{ versionNumber, databaseName }] = await admin.$queryRaw`
      SELECT current_setting('server_version_num')::int AS "versionNumber", current_database() AS "databaseName"
    `;
    assert(versionNumber >= 180000 && versionNumber < 190000, `Expected PostgreSQL 18, received ${versionNumber}`);
    assert.equal(databaseName, expectedDatabase);
    await installProbe(admin);

    const blankRows = await admin.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_authenticated");
      return tx.$queryRaw`SELECT id FROM session_b_wave.actor_record ORDER BY id`;
    });
    assert.deepEqual(blankRows, [], "blank actor context must see no rows");

    const actorRows = await admin.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_authenticated");
      await setActorContext(tx, "actor-a", "licensee-a");
      return tx.$queryRaw`SELECT id, payload FROM session_b_wave.actor_record ORDER BY id`;
    });
    assert.deepEqual(actorRows, [{ id: "actor-own", payload: "own" }]);

    const foreignRows = await admin.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_authenticated");
      await setActorContext(tx, "actor-a", "licensee-b");
      return tx.$queryRaw`SELECT id FROM session_b_wave.actor_record ORDER BY id`;
    });
    assert.deepEqual(foreignRows, [], "conflicting actor and tenant context must see no rows");

    await expectRejected(
      () => admin.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_public");
        return tx.$queryRaw`SELECT id FROM session_b_wave.public_record`;
      }),
      /permission denied/
    );
    const publicRows = await admin.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_public");
      return tx.$queryRaw`SELECT * FROM session_b_wave.read_public_record('public-a', ${"a".repeat(64)})`;
    });
    assert.deepEqual(publicRows, [{ id: "public-a", payload: "safe-public-projection" }]);
    const invalidProofRows = await admin.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_wave_b_public");
      return tx.$queryRaw`SELECT * FROM session_b_wave.read_public_record('public-a', ${"c".repeat(64)})`;
    });
    assert.deepEqual(invalidProofRows, [], "invalid public proof must be non-enumerable");

    const [claimA, claimB] = await Promise.all([claimJob(connectionA), claimJob(connectionB)]);
    assert.equal(claimA.length + claimB.length, 1, "database CAS must have one concurrent winner");

    const [{ leakedUserId, leakedSystemIdentity }] = await admin.$queryRaw`
      SELECT current_setting('app.user_id', true) AS "leakedUserId",
             current_setting('app.system_identity', true) AS "leakedSystemIdentity"
    `;
    assert(!leakedUserId && !leakedSystemIdentity, "transaction-local context must clear after commit");

    console.log(JSON.stringify({
      valid: true,
      databaseName,
      postgresMajor: 18,
      authenticatedBlankForeignDenial: true,
      publicFunctionOnlyBoundary: true,
      workerConcurrentSingleWinner: true,
      transactionContextCleared: true,
    }));
  } finally {
    await Promise.allSettled([admin.$disconnect(), connectionA.$disconnect(), connectionB.$disconnect()]);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
