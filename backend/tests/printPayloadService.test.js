const { resolvePayloadType, supportsNetworkDirectPayloadType, supportsNetworkDirectPayload } = require("../dist/services/printPayloadService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  assert(resolvePayloadType({ commandLanguage: "ZPL" }) === "ZPL", "ZPL printers should resolve to ZPL payloads");
  assert(resolvePayloadType({ commandLanguage: "TSPL" }) === "TSPL", "TSPL printers should resolve to TSPL payloads");
  assert(resolvePayloadType({ commandLanguage: "EPL" }) === "EPL", "EPL printers should resolve to EPL payloads");
  assert(resolvePayloadType({ commandLanguage: "CPCL" }) === "CPCL", "CPCL printers should resolve to CPCL payloads");
  assert(
    resolvePayloadType({ connectionType: "LOCAL_AGENT", commandLanguage: "AUTO" }) === "JSON",
    "Local-agent AUTO printers should resolve to JSON payloads for workstation rendering"
  );
  assert(
    resolvePayloadType({ connectionType: "NETWORK_DIRECT", commandLanguage: "AUTO" }) === "ZPL",
    "Network-direct AUTO printers should still default to ZPL payloads"
  );

  assert(supportsNetworkDirectPayloadType("ZPL"), "ZPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("TSPL"), "TSPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("EPL"), "EPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("CPCL"), "CPCL should be allowed for network-direct dispatch");
  assert(!supportsNetworkDirectPayloadType("JSON"), "JSON payloads must not be treated as network-direct capable");

  assert(
    supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "CPCL" }),
    "Registered CPCL printers should be network-direct capable"
  );
  assert(
    !supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "SBPL" }),
    "SBPL should remain blocked for network-direct until an adapter is added"
  );

  console.log("print payload service tests passed");
};

run();
