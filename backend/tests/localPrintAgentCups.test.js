const {
  parseLpstatPrinters,
  parseDefaultPrinter,
  parseLpstatUris,
  parseLpoptionsDetails,
  parseSystemProfilerPrinters,
  buildCapabilitySummary,
} = require("../dist/local-print-agent/cups");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const lpstat = `
printer Canon_TS4100i_series is idle. enabled since Wed Mar 11 15:24:22 2026
printer Zebra_ZD421 disabled since Wed Mar 11 15:25:22 2026 -
system default destination: Canon_TS4100i_series
`;

  const printers = parseLpstatPrinters(lpstat);
  assert(printers.length === 2, "Expected lpstat parser to return two printers");
  assert(printers[0].printerId === "Canon_TS4100i_series", "Expected first printer id");
  assert(printers[0].online === true, "Idle printer should be online");
  assert(printers[1].online === false, "Disabled printer should be offline");
  assert(parseDefaultPrinter(lpstat) === "Canon_TS4100i_series", "Default printer should be parsed");

  const uriMap = parseLpstatUris(
    "device for Canon_TS4100i_series: dnssd://Canon%20TS4100i%20series._ipps._tcp.local./?uuid=123\n"
  );
  assert(uriMap.get("Canon_TS4100i_series")?.includes("_ipps._tcp"), "Printer URI should be parsed");

  const options = parseLpoptionsDetails(
    "PageSize/Media Size: 4x6 *A4 Letter Custom.WIDTHxHEIGHT\nResolution/Output Resolution: *300dpi 600dpi\n"
  );
  assert(options.mediaSizes.includes("A4"), "Expected media sizes from lpoptions");
  assert(options.dpiOptions.includes(300) && options.dpiOptions.includes(600), "Expected DPI options from lpoptions");

  const profiler = parseSystemProfilerPrinters(
    JSON.stringify({
      SPPrintersDataType: [
        {
          _name: "Canon TS4100i series",
          ppd: "Canon TS4100i series-AirPrint",
          uri: "dnssd://Canon%20TS4100i%20series._ipps._tcp.local./?uuid=123",
          printercommands: "none ",
          status: "idle",
          default: "yes",
        },
      ],
    })
  );
  assert(profiler.length === 1, "Expected one parsed system profiler printer");
  assert(profiler[0].name === "Canon TS4100i series", "Expected friendly printer name");

  const capability = buildCapabilitySummary(
    [
      {
        printerId: "Canon_TS4100i_series",
        printerName: "Canon TS4100i series",
        model: "Canon TS4100i series-AirPrint",
        connection: "ipps",
        online: true,
        isDefault: true,
        protocols: ["dnssd", "ipps"],
        languages: [],
        mediaSizes: ["A4", "Letter"],
        dpi: 600,
      },
    ],
    "Canon_TS4100i_series"
  );
  assert(capability.supportsPdf === true, "Capability summary should report PDF support");
  assert(capability.languages.includes("AUTO"), "Capability summary should fall back to AUTO language");

  console.log("local print agent cups tests passed");
};

run();
