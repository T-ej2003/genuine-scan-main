const assert = require("assert");
const {
  assertSafeDenied,
  ids,
  request,
  tokens,
  withServer,
} = require("./helpers/p1TestApp");

const assertAllowed = ({ status, text }, routeLabel, options = {}) => {
  assert.ok(status >= 200 && status < 300, `${routeLabel} expected 2xx, got ${status}: ${text}`);
  if (!options.allowCrossTenant) {
    assert.doesNotMatch(text, /p1-licensee-b|P1 Brand B|p1-qr-b|p1-batch-b/i, `${routeLabel} leaked cross-tenant fixture data`);
  }
};

(async () => {
  await withServer(async (baseUrl) => {
    assertSafeDenied(await request(baseUrl, "GET", "/api/auth/me", null));
    assertSafeDenied(await request(baseUrl, "GET", "/api/auth/me", tokens.invalid));
    assertAllowed(await request(baseUrl, "GET", "/api/auth/me", tokens.licenseeAdminA), "auth/me licensee");

    assertSafeDenied(await request(baseUrl, "GET", "/api/licensees", null));
    assertSafeDenied(await request(baseUrl, "GET", "/api/licensees", tokens.licenseeAdminA));
    assertSafeDenied(await request(baseUrl, "GET", "/api/licensees/export", tokens.manufacturerA));
    assertAllowed(await request(baseUrl, "GET", "/api/licensees", tokens.superAdmin), "licensees super admin", {
      allowCrossTenant: true,
    });

    assertSafeDenied(await request(baseUrl, "GET", `/api/users?licenseeId=${ids.licenseeB}`, tokens.licenseeAdminA));
    assertSafeDenied(
      await request(baseUrl, "PATCH", `/api/users/${ids.licenseeAdminB}`, tokens.licenseeAdminA, {
        licenseeId: ids.licenseeB,
        name: "Tampered User",
      })
    );
    assertAllowed(await request(baseUrl, "GET", `/api/users?licenseeId=${ids.licenseeA}`, tokens.licenseeAdminA), "users tenant");

    assertSafeDenied(await request(baseUrl, "GET", `/api/manufacturers?licenseeId=${ids.licenseeB}`, tokens.licenseeAdminA));
    assertAllowed(
      await request(baseUrl, "GET", `/api/manufacturers?licenseeId=${ids.licenseeA}`, tokens.licenseeAdminA),
      "manufacturers tenant"
    );

    assertSafeDenied(await request(baseUrl, "GET", `/api/qr/batches?licenseeId=${ids.licenseeB}`, tokens.manufacturerA));
    assertSafeDenied(
      await request(baseUrl, "PATCH", `/api/qr/batches/${ids.batchB}/rename`, tokens.licenseeAdminA, {
        licenseeId: ids.licenseeB,
        name: "Cross Tenant Rename",
      })
    );
    assertAllowed(await request(baseUrl, "GET", `/api/qr/batches?licenseeId=${ids.licenseeA}`, tokens.manufacturerA), "batches tenant");

    assertSafeDenied(await request(baseUrl, "GET", "/api/qr/codes/export", tokens.licenseeAdminA));
    assertSafeDenied(await request(baseUrl, "POST", "/api/qr/codes/signed-links", tokens.licenseeAdminA, { qrIds: [ids.qrA] }));
    assertAllowed(await request(baseUrl, "GET", `/api/qr/codes/export?licenseeId=${ids.licenseeA}`, tokens.superAdmin), "qr export");

    assertSafeDenied(await request(baseUrl, "GET", `/api/qr/requests?licenseeId=${ids.licenseeB}`, tokens.licenseeAdminA));
    assertSafeDenied(
      await request(baseUrl, "POST", "/api/qr/requests", tokens.licenseeAdminA, {
        licenseeId: ids.licenseeB,
        quantity: 10,
        batchName: "Tampered QR Request",
      })
    );
    assertSafeDenied(await request(baseUrl, "POST", `/api/qr/requests/${ids.qrRequestA}/approve`, tokens.licenseeAdminA, {}));
    assertAllowed(
      await request(baseUrl, "GET", `/api/qr/requests?licenseeId=${ids.licenseeA}`, tokens.licenseeAdminA),
      "qr requests tenant"
    );

    assertSafeDenied(await request(baseUrl, "GET", `/api/admin/qr/scan-logs?licenseeId=${ids.licenseeB}`, tokens.manufacturerA));
    assertAllowed(
      await request(baseUrl, "GET", `/api/admin/qr/scan-logs?licenseeId=${ids.licenseeA}`, tokens.manufacturerA),
      "scan logs tenant"
    );

    assertSafeDenied(await request(baseUrl, "GET", `/api/incidents?licenseeId=${ids.licenseeB}`, tokens.licenseeAdminA));
    assertSafeDenied(await request(baseUrl, "GET", `/api/incidents/${ids.incidentB}`, tokens.licenseeAdminA), [403, 404]);
    assertSafeDenied(await request(baseUrl, "PATCH", `/api/incidents/${ids.incidentB}`, tokens.licenseeAdminA, { status: "CLOSED" }));

    assertSafeDenied(await request(baseUrl, "GET", "/api/ir/incidents", tokens.licenseeAdminA));
    assertSafeDenied(await request(baseUrl, "GET", "/api/governance/feature-flags", tokens.manufacturerA));
    assertAllowed(
      await request(baseUrl, "GET", "/api/governance/feature-flags?licenseeId=00000000-0000-4000-8000-0000000000aa", tokens.superAdmin),
      "governance super admin",
      { allowCrossTenant: true }
    );

    assertSafeDenied(await request(baseUrl, "GET", "/api/support/tickets", tokens.licenseeAdminA));
    assertSafeDenied(await request(baseUrl, "GET", `/api/support/reports?licenseeId=${ids.licenseeB}`, tokens.manufacturerA));
    assertAllowed(await request(baseUrl, "GET", "/api/support/reports", tokens.manufacturerA), "support reports tenant");

    assertSafeDenied(await request(baseUrl, "GET", `/api/manufacturer/print-jobs?licenseeId=${ids.licenseeB}`, tokens.manufacturerA));
    assertSafeDenied(await request(baseUrl, "POST", "/api/manufacturer/print-jobs", tokens.licenseeAdminA, { licenseeId: ids.licenseeA }));
    assertSafeDenied(await request(baseUrl, "GET", `/api/manufacturer/print-jobs/${ids.printJobB}/pack`, tokens.manufacturerA), [
      403,
      404,
      410,
    ]);
    assertAllowed(
      await request(baseUrl, "GET", "/api/manufacturer/print-jobs", tokens.manufacturerA),
      "print jobs tenant"
    );
  });

  console.log("p1 real-router API authorization integration test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
