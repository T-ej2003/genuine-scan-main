const {
  buildSetupVerification,
  parseWindowsPrinters,
  resolveSelectedPrinter,
} = require("../dist/local-print-agent/cups");

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

  const localPrinters = printers.map((printer) => ({
    printerId: printer.name,
    printerName: printer.name,
    model: printer.driverName,
    connection: "spooler",
    online: printer.online,
    isDefault: printer.isDefault,
    protocols: [],
    languages: [],
    mediaSizes: [],
    dpi: null,
  }));

  const noPrintersSelection = resolveSelectedPrinter([], null);
  const noPrintersVerification = buildSetupVerification({
    printers: [],
    selection: noPrintersSelection,
    connected: false,
    inventoryError: "No printers detected by the Windows print spooler.",
  });
  assert(noPrintersVerification.state === "NO_PRINTERS", "No printers should return NO_PRINTERS");

  const defaultReadySelection = resolveSelectedPrinter(localPrinters, null);
  const defaultReadyVerification = buildSetupVerification({
    printers: localPrinters,
    selection: defaultReadySelection,
    connected: true,
  });
  assert(defaultReadySelection.selectionSource === "default", "Default online printer should win selection");
  assert(defaultReadyVerification.state === "READY", "Online default printer should verify as READY");

  const offlinePersistedSelection = resolveSelectedPrinter(localPrinters, "Canon Office Printer");
  const offlinePersistedVerification = buildSetupVerification({
    printers: localPrinters,
    selection: offlinePersistedSelection,
    connected: false,
  });
  assert(
    offlinePersistedSelection.selectionSource === "persisted",
    "Persisted printer should stay selected when still present"
  );
  assert(
    offlinePersistedVerification.state === "PRINTER_UNAVAILABLE",
    "Offline persisted printer should verify as PRINTER_UNAVAILABLE"
  );

  const nonDefaultPrinters = [
    { ...localPrinters[0], isDefault: false, online: false, printerName: "Offline Defaultless", printerId: "Offline Defaultless" },
    { ...localPrinters[1], printerName: "Brother Ready", printerId: "Brother Ready", online: true, isDefault: false },
  ];
  const firstOnlineSelection = resolveSelectedPrinter(nonDefaultPrinters, null);
  const firstOnlineVerification = buildSetupVerification({
    printers: nonDefaultPrinters,
    selection: firstOnlineSelection,
    connected: true,
  });
  assert(
    firstOnlineSelection.selectionSource === "first_online",
    "First online non-default printer should be selected when no persisted/default online printer exists"
  );
  assert(firstOnlineVerification.state === "READY", "First online fallback should verify as READY");

  const multiplePrinters = [
    { ...localPrinters[1], printerName: "Offline Canon", printerId: "Offline Canon", online: false, isDefault: false },
    { ...localPrinters[0], printerName: "Zebra Ready", printerId: "Zebra Ready", online: true, isDefault: false },
    { ...localPrinters[0], printerName: "HP Also Ready", printerId: "HP Also Ready", online: true, isDefault: false },
  ];
  const multipleSelection = resolveSelectedPrinter(multiplePrinters, null);
  const multipleVerification = buildSetupVerification({
    printers: multiplePrinters,
    selection: multipleSelection,
    connected: true,
  });
  assert(multipleSelection.printerName === "Zebra Ready", "First online printer should be selected deterministically");
  assert(multipleVerification.onlinePrinterCount === 2, "Online printer count should be reported");
  assert(multipleVerification.state === "READY", "Multiple-printer online scenario should verify as READY");

  console.log("local print agent windows tests passed");
};

run();
