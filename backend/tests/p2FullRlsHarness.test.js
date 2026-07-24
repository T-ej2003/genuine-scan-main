const assert = require("assert");
const { withP2TestApp } = require("./helpers/p2TestDb");

(async () => {
  await withP2TestApp(async ({ runtimePrisma }) => {
    const [catalog] = await runtimePrisma.$queryRawUnsafe(`
      SELECT
        current_setting('server_version_num')::integer / 10000 AS "postgresMajor",
        current_user AS "runtimeRole",
        to_regprocedure('app_auth.require_authenticated_session(text,text,text)') IS NOT NULL AS "authCapability",
        to_regnamespace('app_rls') IS NOT NULL AS "rlsSchema",
        has_table_privilege(current_user, 'public."User"', 'SELECT') AS "directUserSelect"
    `);
    assert.deepStrictEqual(catalog, {
      postgresMajor: 18,
      runtimeRole: "mscqr_rls_cert_app",
      authCapability: true,
      rlsSchema: true,
      directUserSelect: false,
    });
  });
  console.log("P2 PostgreSQL 18 full-RLS harness test passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
