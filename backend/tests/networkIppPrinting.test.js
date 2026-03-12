const { buildIppConnectionInfo } = require("../dist/printing/ippClient");
const { isGatewayFresh } = require("../dist/services/networkIppPrintService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const explicitSecure = buildIppConnectionInfo({
    printerUri: "ipps://canon-office.local/ipp/print",
  });

  assert(
    explicitSecure.endpointUrl === "https://canon-office.local:631/ipp/print",
    "IPPS URIs without an explicit port should default to HTTPS transport on port 631"
  );
  assert(
    explicitSecure.printerUri === "ipps://canon-office.local:631/ipp/print",
    "IPPS printer URI should normalize to port 631 when absent"
  );

  const explicitPlain = buildIppConnectionInfo({
    printerUri: "ipp://canon-office.local/custom/path",
  });

  assert(
    explicitPlain.endpointUrl === "http://canon-office.local:631/custom/path",
    "IPP URIs without an explicit port should default to port 631"
  );

  const derived = buildIppConnectionInfo({
    host: "printer.lan",
    port: 8631,
    resourcePath: "ipp/labels",
    tlsEnabled: false,
  });

  assert(derived.endpointUrl === "http://printer.lan:8631/ipp/labels", "Derived endpoint should normalize path and transport");
  assert(derived.printerUri === "ipp://printer.lan:8631/ipp/labels", "Derived printer URI should match normalized IPP URI");

  assert(isGatewayFresh(new Date().toISOString()), "Fresh gateway heartbeats should be treated as online");
  assert(!isGatewayFresh(new Date(Date.now() - 5 * 60_000).toISOString()), "Stale gateway heartbeats should be treated as offline");

  console.log("network IPP printing tests passed");
};

run();
