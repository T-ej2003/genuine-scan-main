const {
  buildSetupVerification,
  extractWindowsJobId,
  parseWindowsPrinters,
  resolveSelectedPrinter,
  waitForLocalPrintJobCompletion,
} = require("../dist/local-print-agent/cups");
const {
  isRawWindowsZplPayload,
  validateZplPayloadForRawPrint,
} = require("../dist/local-print-agent/render");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
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

  const zdesignerWithVirtualPrinters = [
    {
      printerId: "Fax",
      printerName: "Fax",
      model: "Microsoft Shared Fax Driver",
      connection: "spooler",
      online: true,
      isDefault: false,
      protocols: [],
      languages: [],
      mediaSizes: [],
      dpi: null,
    },
    {
      printerId: "ZDesigner ZT410-300dpi ZPL",
      printerName: "ZDesigner ZT410-300dpi ZPL",
      model: "ZDesigner ZT410-300dpi ZPL",
      connection: "usb",
      online: true,
      isDefault: true,
      protocols: ["usb"],
      languages: ["ZPL"],
      mediaSizes: [],
      dpi: null,
    },
  ];
  const repairedFaxSelection = resolveSelectedPrinter(zdesignerWithVirtualPrinters, "Fax");
  assert(
    repairedFaxSelection.printerId === "ZDesigner ZT410-300dpi ZPL",
    "Persisted Fax selection should repair to the online ZDesigner printer"
  );

  const faxOnlySelection = resolveSelectedPrinter([zdesignerWithVirtualPrinters[0]], "Fax");
  const faxOnlyVerification = buildSetupVerification({
    printers: [zdesignerWithVirtualPrinters[0]],
    selection: faxOnlySelection,
    connected: true,
  });
  assert(faxOnlyVerification.state === "PRINTER_UNAVAILABLE", "Fax alone must not verify as MSCQR ready");

  assert(
    extractWindowsJobId("winspool:ZDesigner ZT410-300dpi ZPL:1779493447676") === null,
    "Timestamp-based legacy winspool refs must not be treated as Windows PrintJob IDs"
  );
  assert(
    extractWindowsJobId("winspool-id:ZDesigner ZT410-300dpi ZPL:42") === 42,
    "Real Windows spooler job IDs should remain confirmable"
  );
  assert(
    extractWindowsJobId("winspool-opaque:ZDesigner ZT410-300dpi ZPL:abc123") === null,
    "Opaque Windows dispatch refs should skip Get-PrintJob confirmation"
  );
  const unavailableConfirmation = await waitForLocalPrintJobCompletion({
    printerId: "ZDesigner ZT410-300dpi ZPL",
    jobRef: null,
  });
  assert(
    unavailableConfirmation.confirmationUnavailable === true && unavailableConfirmation.confirmed === false,
    "Missing or opaque spooler refs should not be converted into physical printer failures"
  );

  const validZpl = `^XA\n^PW590\n^LL590\n^LH0,0\n^CI28\n^FO24,24^BQN,2,7^FDLA,https://mscqr.example.test/scan/${"a".repeat(100)}^FS\n^XZ`;
  assert(
    isRawWindowsZplPayload({ payloadType: "ZPL", labelLanguage: "ZPL", payloadContent: validZpl }),
    "Windows ZPL payloads should be routed to the RAW spooler path"
  );
  assert(validateZplPayloadForRawPrint(validZpl) === validZpl, "Valid ZPL should pass raw-print validation");
  assert(
    Buffer.byteLength(validateZplPayloadForRawPrint(validZpl), "utf8") === Buffer.byteLength(validZpl, "utf8"),
    "Raw ZPL bytesWritten should be based on actual payload bytes, not payload hash length"
  );
  let shortZplRejected = false;
  try {
    validateZplPayloadForRawPrint("^XA\n^FO0,0^BQN,2,7^FDLA,x^FS\n^XZ");
  } catch (error) {
    shortZplRejected = true;
    assert(error.errorCode === "invalid_zpl_print_payload", "Short/placeholder ZPL should fail with a precise code");
  }
  assert(shortZplRejected, "Tiny ZPL must not be sent to a Zebra as a production label");

  let blackBlockRejected = false;
  try {
    validateZplPayloadForRawPrint("^XA\n^PW600\n^LL400\n^FO0,0^GB600,400,390,B,0^FS\n^XZ");
  } catch (error) {
    blackBlockRejected = true;
    assert(
      error.zplValidationErrors.includes("zpl_full_label_black_box_risk"),
      "Full-label black block ZPL should be rejected before print"
    );
  }
  assert(blackBlockRejected, "Black-block-risk payload must not reach the Windows RAW spooler");

  const multiplePrinters = [
    { ...localPrinters[1], printerName: "Offline Canon", printerId: "Offline Canon", online: false, isDefault: false },
    { ...localPrinters[0], printerName: "Zebra Ready", printerId: "Zebra Ready", online: true, isDefault: false },
    {
      ...localPrinters[0],
      printerName: "HP Also Ready",
      printerId: "HP Also Ready",
      model: "HP Universal Printing",
      online: true,
      isDefault: false,
    },
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

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
