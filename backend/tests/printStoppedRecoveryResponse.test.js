const assert = require("node:assert/strict");

const workflow = require("../dist/services/printReissueRequestWorkflowService");
const repository = require("../dist/rls-waves/session-c/c02/printingLifecycleRepository");
const { localAgentErrorResponse } = require("../dist/controllers/printerAgentJobController");
const { createManufacturerPrintReissueRequest, getManufacturerPrintJobStatus, listManufacturerPrintJobs } = require("../dist/controllers/print-job/queryHandlers");

const originalCreate = workflow.createScopedPrintReissueRequest;
const originalRead = repository.readPrintingProjection;
const originalError = console.error;
const response = {
  statusCode: 200,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
};

async function main() {
  workflow.createScopedPrintReissueRequest = async () => {
    const error = new Error("Raw query failed");
    error.code = "P2010";
    error.meta = { code: "P0001", message: "ERROR: PHYSICAL_OUTCOME_UNCONFIRMED\n" };
    throw error;
  };
  console.error = () => undefined;
  try {
    await createManufacturerPrintReissueRequest({
      user: { role: "MANUFACTURER_ADMIN", userId: "50000000-0000-4000-8000-000000000301" },
      params: { id: "50000000-0000-4000-8000-000000000501" },
      body: { reason: "Stopped before dispatch" },
      databaseSessionCapability: "test-capability",
      requestId: "test-request",
    }, response);
    assert.equal(response.statusCode, 409);
    assert.equal(response.body.code, "PHYSICAL_OUTCOME_UNCONFIRMED");
    assert.match(response.body.error, /Physical output is uncertain/);

    repository.readPrintingProjection = async () => { throw new Error("SENSITIVE_SQL_DETAIL"); };
    const req = {
      user: { role: "MANUFACTURER_ADMIN", userId: "50000000-0000-4000-8000-000000000301" },
      params: { id: "50000000-0000-4000-8000-000000000501" },
      query: {},
      databaseSessionCapability: "test-capability",
      requestId: "test-request",
    };
    await listManufacturerPrintJobs(req, response);
    assert.equal(response.statusCode, 500);
    assert.equal(response.body.error, "Print jobs could not be loaded.");
    await getManufacturerPrintJobStatus(req, response);
    assert.equal(response.statusCode, 500);
    assert.equal(response.body.error, "Print job status could not be loaded.");
    localAgentErrorResponse(response, { message: "SENSITIVE_SQL_DETAIL", errorCode: "P2010" });
    assert.equal(response.statusCode, 500);
    assert.equal(response.body.error, "Internal server error");
    assert.equal(response.body.code, undefined);
    localAgentErrorResponse(response, { statusCode: 409, message: "Connector update required", errorCode: "CONNECTOR_UPDATE_REQUIRED" });
    assert.equal(response.body.error, "Connector update required");
    assert.equal(response.body.code, "CONNECTOR_UPDATE_REQUIRED");
  } finally {
    workflow.createScopedPrintReissueRequest = originalCreate;
    repository.readPrintingProjection = originalRead;
    console.error = originalError;
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
