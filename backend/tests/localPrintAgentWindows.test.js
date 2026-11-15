const {
  buildSetupVerification,
  extractWindowsJobId,
  listWindowsLocalPrinters,
  parseWindowsPrinterDiscovery,
  parseWindowsPrinters,
  applyConfirmedZplCapabilities,
  isVirtualNonLabelPrinter,
  zplPrinterIdentity,
  resolveSelectedPrinter,
  waitForLocalPrintJobCompletion,
} = require("../dist/local-print-agent/cups");
const {
  isRawWindowsZplPayload,
  printLabel,
  validateZplPayloadForRawPrint,
} = require("../dist/local-print-agent/render");
const {
  ZPL_300DPI_COMPATIBILITY_CONTRACT,
  buildOfficialMscqrWordmarkGfaCommand,
  classifyIndustrialZplPrinterProfile,
} = require("../dist/printing/zplCompatibilityContract");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { mergeCalibrationProfile } = require("../dist/local-print-agent/state");
const { getZplPayloadSafetyIssues } = require("../dist/printing/printPayloadSafety");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const assertProductionSpoolContract = (zpl, scanUrl) => {
  const contract = ZPL_300DPI_COMPATIBILITY_CONTRACT;
  assert(zpl.startsWith("^XA\n") && zpl.endsWith("^XZ") && (zpl.match(/\^XZ/g) || []).length === 1,
    "RAW spool input must contain one complete ZPL label");
  assert(zpl.includes(`^PW${contract.labelWidthDots}\n^LL${contract.labelHeightDots}\n^LH0,0\n^CI28\n`),
    "RAW spool input must use the certified 300dpi label dimensions and origin");
  assert(["PW", "LL", "LH", "CI"].every((command) => (zpl.match(new RegExp(`\\^${command}`, "g")) || []).length === 1) &&
    !/\^(?:LS|LT|LR|PO|FW)/.test(zpl), "RAW spool input must not override the certified geometry");
  const boxes = [...zpl.matchAll(/\^GB(\d+),(\d+),(\d+),B,0/g)];
  assert(boxes.length === 1 && (zpl.match(/\^GB/g) || []).length === 1 &&
    Number(boxes[0][2]) === 2 && Number(boxes[0][3]) === 2,
    "Production ZPL may contain only its thin separator, not a filled black box");
  const qrFields = [...zpl.matchAll(/\^FO(\d+),(\d+)\^BQN,2,(\d+)\^FDLA,([^\^~]+)\^FS/g)];
  assert(qrFields.length === 1 && (zpl.match(/\^BQ/g) || []).length === 1 && qrFields[0][4] === scanUrl,
    "RAW spool input must encode the approved URL in exactly one native QR field");
  const [, x, y, magnification] = qrFields[0];
  assert(Number(x) >= contract.qrBox.xMin && Number(x) <= contract.qrBox.xMax &&
    Number(y) >= contract.qrBox.yMin && Number(y) <= contract.qrBox.yMax &&
    Number(magnification) >= 2 && Number(magnification) <= 10,
    "Native QR must fit the certified 300dpi printer profile");
  assert(!/\^(?:G[A-Z]|XG|FR)/.test(zpl.slice(qrFields[0].index + qrFields[0][0].length)),
    "No later graphic or reverse field may obscure the QR");
  assert(getZplPayloadSafetyIssues({ payloadContent: zpl }).issues.length === 0,
    "RAW spool input must pass the production ZPL safety contract");
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

  const compatible = parseWindowsPrinters(JSON.stringify({ printers: [
    { Name: "TSC emulation", DriverName: "TSC ZPL 300dpi", PortName: "USB002", PrinterStatus: 3 },
    { Name: "Zebra ZPL 300dpi", DriverName: "Generic / Text Only", PortName: "USB003", PrinterStatus: 3 },
    { Name: "Unknown industrial label", DriverName: "Generic Label Driver", PortName: "USB004", PrinterStatus: 3 },
    { Name: "Other language", DriverName: "TSPL 300dpi", PortName: "USB005", PrinterStatus: 3 },
  ] }));
  assert(compatible[0].languages.includes("ZPL") && compatible[0].dpi === 300, "Emulation driver should advertise ZPL and DPI");
  assert(compatible[1].languages.length === 0 && compatible[1].dpi === null, "Brand and queue name must not assert driver capabilities");
  const unknown = { printerId: compatible[2].name, printerName: compatible[2].name, model: compatible[2].driverName, connection: "usb", online: true, isDefault: false, protocols: [], languages: compatible[2].languages, mediaSizes: [], dpi: compatible[2].dpi };
  const confirmation = { zplCompatible: true, dpi: 300, zplPrinterIdentity: zplPrinterIdentity(unknown) };
  const confirmed = applyConfirmedZplCapabilities(unknown, confirmation);
  assert(confirmed.languages.includes("ZPL") && confirmed.dpi === 300, "Operator confirmation should enable unknown compatible device");
  assert(applyConfirmedZplCapabilities(unknown, { ...confirmation, zplCompatible: false }).languages.length === 0, "Unconfirmed mode must remain unknown");
  assert(applyConfirmedZplCapabilities({ ...unknown, portName: "USB005" }, confirmation).languages.length === 0, "Confirmation must expire if the printer port changes");
  assert(applyConfirmedZplCapabilities({ ...unknown, languages: compatible[3].languages }, confirmation).languages.every((language) => language !== "ZPL"), "Conflicting driver language must not be overridden");
  const virtualZpl = { ...unknown, printerId: "Microsoft Print to PDF", printerName: "Microsoft Print to PDF", languages: ["ZPL"], dpi: 300 };
  assert(isVirtualNonLabelPrinter(virtualZpl), "A virtual queue must remain blocked even if it advertises ZPL");
  const virtualUnknown = { ...virtualZpl, languages: [] };
  assert(applyConfirmedZplCapabilities(virtualUnknown, { ...confirmation, zplPrinterIdentity: zplPrinterIdentity(virtualUnknown) }).languages.length === 0,
    "Operator confirmation must not turn a virtual queue into a physical printer");
  const calibrated = mergeCalibrationProfile({ calibrationProfiles: { [unknown.printerId]: { zplCompatible: true, dpi: 300, offsetXmm: 2 } } }, unknown.printerId, { darkness: 8 });
  assert(calibrated.calibrationProfiles[unknown.printerId].zplCompatible === true && calibrated.calibrationProfiles[unknown.printerId].offsetXmm === 2, "Updating calibration must preserve operator confirmation and existing offsets");

  const localPrinters = printers.map((printer) => ({
    printerId: printer.name,
    printerName: printer.name,
    model: printer.driverName,
    connection: "spooler",
    online: printer.online,
    isDefault: printer.isDefault,
    protocols: [],
    languages: printer.languages,
    mediaSizes: [],
    dpi: printer.dpi,
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
  if (process.platform !== "win32") {
    const fakeTools = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-windows-queue-"));
    const originalPath = process.env.PATH;
    const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
    try {
      fs.writeFileSync(path.join(fakeTools, "powershell.exe"), "#!/bin/sh\nprintf 'DONE'\n", { mode: 0o700 });
      process.env.PATH = `${fakeTools}:${originalPath}`;
      Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
      const queueGone = await waitForLocalPrintJobCompletion({
        printerId: "ZDesigner ZT410-300dpi ZPL",
        jobRef: "winspool-id:ZDesigner ZT410-300dpi ZPL:42",
        timeoutMs: 1000,
      });
      assert(queueGone.confirmed === false && queueGone.confirmationUnavailable === true,
        "A missing Windows queue entry must not prove physical printing");
    } finally {
      Object.defineProperty(process, "platform", originalPlatform);
      process.env.PATH = originalPath;
      fs.rmSync(fakeTools, { recursive: true, force: true });
    }
  }

  const productionPayload = JSON.parse(execFileSync(process.execPath,
    [path.join(__dirname, "fixtures/productionWindowsZplPayload.js")], { encoding: "utf8" }));
  const validZpl = productionPayload.payloadContent;
  assert(productionPayload.payloadType === "ZPL" && isRawWindowsZplPayload({
    payloadType: productionPayload.payloadType, labelLanguage: productionPayload.commandLanguage,
    payloadContent: validZpl,
  }), "AUTO ZPL-capable printer must select RAW ZPL, not bitmap fallback");
  if (process.platform !== "win32") {
    const fakeTools = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-windows-raw-capture-"));
    const capturePath = path.join(fakeTools, "captured.zpl");
    const originalPath = process.env.PATH;
    const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
    try {
      fs.writeFileSync(path.join(fakeTools, "powershell.exe"), [
        "#!/bin/sh",
        "while [ \"$#\" -gt 0 ]; do",
        "  if [ \"$1\" = \"-PayloadPath\" ]; then shift; cp \"$1\" \"$MSCQR_TEST_CAPTURE_PATH\"; fi",
        "  shift",
        "done",
        "printf 'JOB_ID=42\\nRAW_WRITTEN=1\\n'",
      ].join("\n"), { mode: 0o700 });
      process.env.PATH = `${fakeTools}:${originalPath}`;
      process.env.MSCQR_TEST_CAPTURE_PATH = capturePath;
      Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
      const result = await printLabel({
        printerId: "ZDesigner ZT410-300dpi ZPL",
        printerName: "ZDesigner ZT410-300dpi ZPL",
        printerLanguages: ["ZPL"],
        printerDpi: 300,
        request: {
          code: productionPayload.publicVerifyCode,
          scanUrl: productionPayload.scanUrl,
          payloadType: productionPayload.payloadType,
          payloadContent: validZpl,
          payloadHash: productionPayload.payloadHash,
          copies: 1,
          printPath: "auto",
          labelLanguage: productionPayload.commandLanguage,
        },
      });
      assert(result.printPath === "windows-raw-zpl", "Production ZPL must select the Windows RAW spooler");
      const approvedBytes = Buffer.from(validZpl, "utf8");
      const assertApprovedBytes = (bytes) => assert(bytes.equals(approvedBytes),
        "The final spooler input must contain the exact approved ZPL bytes");
      const capturedBytes = fs.readFileSync(capturePath);
      assertApprovedBytes(capturedBytes);
      const capturedZpl = capturedBytes.toString("utf8");
      assertProductionSpoolContract(capturedZpl, productionPayload.scanUrl);
      const qrField = capturedZpl.match(/\^FO\d+,\d+\^BQN,2,\d+\^FDLA,[^\^~]+\^FS/)[0];
      const corruptions = [
        capturedZpl.replace(qrField, "^FO90,150^GFA,4,4,1,FFFFFFFF^FS"),
        capturedZpl.replace("^BQN,2,", "^BQN,3,"),
        capturedZpl.replace("^FDLA,", "^FDXX,"),
        capturedZpl.replace(productionPayload.scanUrl, "https://mscqr.example.test/wrong"),
        capturedZpl.slice(0, -3),
        capturedZpl.replace(`^PW${ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots}`, "^PW999"),
        capturedZpl.replace("^LH0,0", "^LH100,100"),
        capturedZpl.replace("^XZ", "^FO90,150^GB350,350,350,B,0^FS\n^XZ"),
        capturedZpl.replace(qrField, `^FO90,150^GB300,300,300,B,0^FS\n${qrField}`),
      ];
      for (const corrupted of corruptions) {
        let rejected = false;
        try { assertProductionSpoolContract(corrupted, productionPayload.scanUrl); } catch { rejected = true; }
        assert(rejected, "Each corrupted production ZPL payload must fail the spool contract");
      }
      let corruptedBytesRejected = false;
      try { assertApprovedBytes(Buffer.from(`${capturedZpl}^XA`, "utf8")); } catch { corruptedBytesRejected = true; }
      assert(corruptedBytesRejected, "A corrupted RAW spool file must not match the approved payload");
      assert(!isRawWindowsZplPayload({ payloadType: "JSON", labelLanguage: "AUTO", payloadContent: "{}" }),
        "A bitmap fallback must not be classified as Windows RAW ZPL");
    } finally {
      Object.defineProperty(process, "platform", originalPlatform);
      process.env.PATH = originalPath;
      delete process.env.MSCQR_TEST_CAPTURE_PATH;
      fs.rmSync(fakeTools, { recursive: true, force: true });
    }
  }
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
    isRawWindowsZplPayload({ payloadType: "ZPL", labelLanguage: "AUTO", payloadContent: validZpl }),
    "AUTO labels resolved as validated ZPL should use the RAW spooler path"
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
    validateZplPayloadForRawPrint("^XA\n^FO0,0^BQN,2,7^FDLA,x^FS\n^XZ", { printerLanguages: ["ZPL"], printerDpi: 300 });
  } catch (error) {
    shortZplRejected = true;
    assert(error.errorCode === "invalid_zpl_print_payload", "Short/placeholder ZPL should fail with a precise code");
  }
  assert(shortZplRejected, "Tiny ZPL must not be sent to a Zebra as a production label");

  let blackBlockRejected = false;
  try {
    validateZplPayloadForRawPrint("^XA\n^PW600\n^LL400\n^FO0,0^GB600,400,390,B,0^FS\n^XZ", { printerLanguages: ["ZPL"], printerDpi: 300 });
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
      languages: [],
      dpi: null,
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
