const {
  buildSetupVerification,
  extractWindowsJobId,
  listWindowsLocalPrinters,
  parseWindowsPrinterDiscovery,
  parseWindowsPrinters,
  resolveSelectedPrinter,
  waitForLocalPrintJobCompletion,
} = require("../dist/local-print-agent/cups");
const {
  isRawWindowsZplPayload,
  validateZplPayloadForRawPrint,
} = require("../dist/local-print-agent/render");
const {
  ZPL_300DPI_COMPATIBILITY_CONTRACT,
  buildOfficialMscqrWordmarkGfaCommand,
  classifyIndustrialZplPrinterProfile,
} = require("../dist/printing/zplCompatibilityContract");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
  const printers = parseWindowsPrinters(
    JSON.stringify({
      printers: [
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
          Name: "MSCQR Zebra ZT410 WiFi",
          DriverName: "ZDesigner ZT410-300dpi ZPL",
          PortName: "MSCQR-ZT410-WIFI-9100",
          WorkOffline: false,
          Default: false,
          PrinterStatus: "Error",
          ExtendedPrinterStatus: 2,
        },
      ],
      ports: [
        { Name: "MSCQR-ZT410-WIFI-9100", PrinterHostAddress: "10.45.144.9", PortNumber: 9100 },
        { Name: "USB001", PrinterHostAddress: null, PortNumber: null },
      ],
      jobs: [
        { PrinterName: "MSCQR Zebra ZT410 WiFi", ID: 43, Name: "MSCQR label", JobStatus: "Error, Printing, Retained" },
        { PrinterName: "MSCQR Zebra ZT410 WiFi", ID: 44, Name: "MSCQR label", JobStatus: "Normal" },
      ],
    })
  );

  assert(printers.length === 2, "Expected two parsed Windows printers");
  assert(printers[0].name === "Zebra ZD421", "Expected printer name");
  assert(printers[0].online === true, "Online Windows printer should be marked online");
  assert(printers[0].isDefault === true, "Default Windows printer should be preserved");
  assert(printers[0].dpi === 203, "Windows ZPL driver names should expose detected 203dpi profiles");
  assert(printers[1].dpi === 300, "Windows ZPL driver names should expose detected 300dpi profiles");
  assert(printers[0].languages.includes("ZPL"), "Windows ZPL driver names should expose the ZPL language");
  assert(printers[1].online === false, "Windows queue errors should be marked offline");
  assert(printers[1].portHost === "10.45.144.9", "TCP/IP port host should be preserved");
  assert(printers[1].portNumber === 9100, "TCP/IP port number should be preserved");
  assert(printers[1].stuckJobCount === 1, "Stuck retained MSCQR jobs should be counted");

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
    portName: printer.portName,
    windowsPortName: printer.portName,
    windowsPortHost: printer.portHost,
    windowsPortNumber: printer.portNumber,
    queueStatus: printer.queueStatus,
    queueHasErrors: printer.queueHasErrors,
    stuckJobCount: printer.stuckJobCount,
    retainedJobCount: printer.retainedJobCount,
    usbAvailable: printer.portName === "USB001" && printer.online,
  }));

  const noPrintersSelection = resolveSelectedPrinter([], null);
  const noPrintersVerification = buildSetupVerification({
    printers: [],
    selection: noPrintersSelection,
    connected: false,
    inventoryError: "No printers detected by the Windows print spooler.",
  });
  assert(noPrintersVerification.state === "NO_PRINTERS", "No printers should return NO_PRINTERS");

  const fallbackDiscovery = parseWindowsPrinterDiscovery(
    JSON.stringify({
      primaryPrinters: [],
      fallbackPrinters: [
        {
          Name: "ZDesigner ZT410-300dpi ZPL",
          DriverName: "ZDesigner ZT410-300dpi ZPL",
          PortName: "USB001",
          WorkOffline: false,
          Default: true,
          PrinterStatus: 3,
          ExtendedPrinterStatus: 2,
        },
        {
          Name: "MSCQR Zebra ZT410 WiFi",
          DriverName: "ZDesigner ZT410-300dpi ZPL",
          PortName: "MSCQR-ZT410-WIFI-9100",
          WorkOffline: false,
          Default: false,
          PrinterStatus: 3,
          ExtendedPrinterStatus: 2,
        },
      ],
      ports: [{ Name: "USB001", PrinterHostAddress: null, PortNumber: null }],
      jobs: [],
      primaryError: null,
      fallbackError: null,
    })
  );
  assert(fallbackDiscovery.diagnostics.primaryEnumerationCount === 0, "Primary discovery count should be tracked");
  assert(fallbackDiscovery.diagnostics.fallbackEnumerationCount === 2, "Fallback discovery count should be tracked");
  assert(fallbackDiscovery.diagnostics.selectedSource === "cim", "CIM should be selected when Get-Printer returns no printers");
  assert(
    fallbackDiscovery.rows.some((printer) => printer.name === "ZDesigner ZT410-300dpi ZPL" && printer.portName === "USB001"),
    "Fallback discovery should include the Zebra USB queue"
  );
  const fallbackLocalPrinters = fallbackDiscovery.rows.map((printer) => ({
    printerId: printer.name,
    printerName: printer.name,
    model: printer.driverName,
    connection: printer.portName === "USB001" ? "usb" : "network",
    online: printer.portName === "USB001",
    isDefault: printer.isDefault,
    protocols: printer.portName === "USB001" ? ["usb"] : ["tcp"],
    languages: ["ZPL"],
    mediaSizes: [],
    dpi: null,
    portName: printer.portName,
    windowsPortName: printer.portName,
    queueStatus: printer.queueStatus,
    queueHasErrors: printer.portName !== "USB001",
    discoverySource: printer.discoverySource,
  }));
  const fallbackSelection = resolveSelectedPrinter(fallbackLocalPrinters, null);
  const fallbackVerification = buildSetupVerification({
    printers: fallbackLocalPrinters,
    selection: fallbackSelection,
    connected: fallbackSelection.printer?.online === true,
  });
  assert(
    fallbackSelection.printerId === "ZDesigner ZT410-300dpi ZPL",
    "Fallback inventory should prefer the real Zebra USB queue over stale WiFi"
  );
  assert(fallbackVerification.state !== "NO_PRINTERS", "Fallback USB discovery must not report NO_PRINTERS");
  assert(fallbackVerification.state === "READY", "Fallback USB discovery should verify READY");

  const toUtf16LeWithBom = (value) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(value, "utf16le")]);
  const packagedRuntimeDiscovery = await listWindowsLocalPrinters({
    execPowerShellJsonCommand: async (commandName, command) => {
      assert(command.includes("ConvertTo-Json"), "Windows discovery commands must use JSON output");
      if (commandName === "powershell-get-printer") {
        return {
          commandPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          exitCode: 0,
          stdout: "[]",
          stderr: "",
        };
      }
      if (commandName === "cim") {
        return {
          commandPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          exitCode: 0,
          stdout: toUtf16LeWithBom(
            JSON.stringify([
              {
                Name: "ZDesigner ZT410-300dpi ZPL",
                DriverName: "ZDesigner ZT410-300dpi ZPL",
                PortName: "USB001",
                WorkOffline: false,
                Default: true,
                Local: true,
                Network: false,
                PrinterStatus: 3,
              },
              {
                Name: "MSCQR Zebra ZT410 WiFi",
                DriverName: "ZDesigner ZT410-300dpi ZPL",
                PortName: "MSCQR-ZT410-WIFI-9100",
                WorkOffline: false,
                Default: false,
                Local: false,
                Network: true,
                PrinterStatus: 3,
              },
            ])
          ),
          stderr: "",
        };
      }
      return {
        commandPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        exitCode: 0,
        stdout: JSON.stringify([{ Name: "USB001", PrinterHostAddress: null, PortNumber: null }]),
        stderr: "",
      };
    },
    portProbe: async () => false,
  });
  assert(packagedRuntimeDiscovery.error === null, "Mocked packaged discovery should not return an error");
  assert(
    packagedRuntimeDiscovery.diagnostics.primaryEnumerationCount === 0,
    "Mocked Get-Printer empty result should be counted"
  );
  assert(
    packagedRuntimeDiscovery.diagnostics.fallbackEnumerationCount === 2,
    "Mocked CIM UTF-16 JSON result should be counted"
  );
  assert(
    packagedRuntimeDiscovery.diagnostics.selectedSource === "cim",
    "Mocked packaged discovery should use CIM when Get-Printer is empty"
  );
  assert(
    packagedRuntimeDiscovery.diagnostics.commands.fallback.stdoutLength > 0 &&
      packagedRuntimeDiscovery.diagnostics.commands.fallback.rawStdoutSample.includes("ZDesigner ZT410-300dpi ZPL"),
    "Fallback command diagnostics should expose safe stdout evidence"
  );
  assert(
    packagedRuntimeDiscovery.printers.some(
      (printer) =>
        printer.printerName === "ZDesigner ZT410-300dpi ZPL" &&
        printer.portName === "USB001" &&
        printer.online === true &&
        printer.usbAvailable === true
    ),
    "Mocked packaged discovery should return the USB Zebra printer"
  );
  const mockedWifiQueue = packagedRuntimeDiscovery.printers.find(
    (printer) => printer.printerName === "MSCQR Zebra ZT410 WiFi"
  );
  assert(mockedWifiQueue && mockedWifiQueue.online === false, "Stale WiFi queue must be unavailable without TCP 9100");
  assert(
    resolveSelectedPrinter(packagedRuntimeDiscovery.printers, null).printerId === "ZDesigner ZT410-300dpi ZPL",
    "Packaged discovery should select USB Zebra over stale WiFi"
  );

  const defaultReadySelection = resolveSelectedPrinter(localPrinters, null);
  const defaultReadyVerification = buildSetupVerification({
    printers: localPrinters,
    selection: defaultReadySelection,
    connected: true,
  });
  assert(defaultReadySelection.selectionSource === "default", "Default online printer should win selection");
  assert(defaultReadyVerification.state === "READY", "Online default printer should verify as READY");

  const offlinePersistedSelection = resolveSelectedPrinter(localPrinters, "MSCQR Zebra ZT410 WiFi");
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
    { ...localPrinters[1], printerName: "Brother Ready", printerId: "Brother Ready", online: true, isDefault: false, queueHasErrors: false },
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

  const validZpl = [
    "^XA",
    `^PW${ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots}`,
    `^LL${ZPL_300DPI_COMPATIBILITY_CONTRACT.labelHeightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO102,16${buildOfficialMscqrWordmarkGfaCommand()}^FS`,
    "^FO90,150^BQN,2,5^FDLA,https://mscqr.example.test/scan/c_connector_contract^FS",
    "^XZ",
  ].join("\n");
  const mutateOfficialGraphicCommand = () => {
    const command = buildOfficialMscqrWordmarkGfaCommand();
    const prefix = command.slice(0, command.lastIndexOf(",") + 1);
    const data = command.slice(prefix.length);
    const finalNibble = data.slice(-1);
    return `${prefix}${data.slice(0, -1)}${finalNibble === "0" ? "1" : "0"}`;
  };
  assert(
    isRawWindowsZplPayload({ payloadType: "ZPL", labelLanguage: "ZPL", payloadContent: validZpl }),
    "Windows ZPL payloads should be routed to the RAW spooler path"
  );
  assert(
    validateZplPayloadForRawPrint(validZpl, {
      printerName: "Honeywell 300dpi ZPL",
      printerLanguages: ["ZPL"],
      printerDpi: 300,
    }) === validZpl,
    "Valid official-wordmark ZPL should pass raw-print validation for generic 300dpi ZPL printers"
  );
  assert(
    Buffer.byteLength(validateZplPayloadForRawPrint(validZpl, { printerName: "TSC 300dpi ZPL", printerLanguages: ["ZPL"], printerDpi: 300 }), "utf8") === Buffer.byteLength(validZpl, "utf8"),
    "Raw ZPL bytesWritten should be based on actual payload bytes, not payload hash length"
  );
  for (const printerName of [
    "ZDesigner ZT410-300dpi ZPL",
    "ZDesigner ZT411-300dpi ZPL",
    "Honeywell 300dpi ZPL",
    "TSC 300dpi ZPL",
    "Printronix 300dpi ZPL",
  ]) {
    const profile = classifyIndustrialZplPrinterProfile({ printerName, printerLanguages: ["ZPL"], printerDpi: 300 });
    assert(profile.compatible && profile.profileId, `${printerName} should be accepted by the generic 300dpi ZPL contract`);
    assert(
      validateZplPayloadForRawPrint(validZpl, { printerName, printerLanguages: ["ZPL"], printerDpi: 300 }) === validZpl,
      `${printerName} should pass connector payload validation without Zebra-only assumptions`
    );
  }
  let genericTextOnlyRejected = false;
  try {
    validateZplPayloadForRawPrint(validZpl, {
      printerName: "Generic / Text Only",
      printerLanguages: [],
      printerDpi: 300,
    });
  } catch (error) {
    genericTextOnlyRejected = true;
    assert(error.errorCode === "unsupported_printer_language", "Generic / Text Only must fail before RAW ZPL dispatch");
  }
  assert(genericTextOnlyRejected, "Generic / Text Only should be rejected for production ZPL labels");
  let unsupportedDpiRejected = false;
  try {
    validateZplPayloadForRawPrint(validZpl, {
      printerName: "ZDesigner ZT410-203dpi ZPL",
      printerLanguages: ["ZPL"],
      printerDpi: 203,
    });
  } catch (error) {
    unsupportedDpiRejected = true;
    assert(error.errorCode === "unsupported_printer_dpi", "203dpi ZPL must fail until scaling is certified");
  }
  assert(unsupportedDpiRejected, "Unsupported DPI should be rejected before RAW ZPL dispatch");
  let mutatedOfficialRejected = false;
  try {
    validateZplPayloadForRawPrint(validZpl.replace(buildOfficialMscqrWordmarkGfaCommand(), mutateOfficialGraphicCommand()), {
      printerName: "ZDesigner ZT410-300dpi ZPL",
      printerLanguages: ["ZPL"],
      printerDpi: 300,
    });
  } catch (error) {
    mutatedOfficialRejected = true;
    assert(error.errorCode === "invalid_zpl_print_payload", "Mutated official graphics should fail connector safety validation");
    assert(
      error.zplValidationErrors.includes("zpl_official_wordmark_hash_mismatch"),
      "Mutated official graphics should report a hash mismatch"
    );
  }
  assert(mutatedOfficialRejected, "Mutated official wordmark graphic must not reach the RAW spooler");
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
