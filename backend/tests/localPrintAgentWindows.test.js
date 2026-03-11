const { parseWindowsPrinters } = require("../dist/local-print-agent/cups");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const printers = parseWindowsPrinters(
    JSON.stringify([
      {
        Name: "Zebra ZD421",
        DriverName: "ZDesigner ZD421-203dpi ZPL",
        PortName: "USB001",
        WorkOffline: false,
        Default: true,
        PrinterStatus: 3,
        ExtendedPrinterStatus: 2,
      },
      {
        Name: "Canon Office Printer",
        DriverName: "Canon Generic Plus UFR II",
        PortName: "WSD-12345",
        WorkOffline: true,
        Default: false,
        PrinterStatus: 7,
        ExtendedPrinterStatus: 7,
      },
    ])
  );

  assert(printers.length === 2, "Expected two parsed Windows printers");
  assert(printers[0].name === "Zebra ZD421", "Expected printer name");
  assert(printers[0].online === true, "Online Windows printer should be marked online");
  assert(printers[0].isDefault === true, "Default Windows printer should be preserved");
  assert(printers[1].online === false, "Offline Windows printer should be marked offline");

  console.log("local print agent windows tests passed");
};

run();
