const fs = require("fs");
const path = require("path");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const packagingScriptPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "build-connector-release.mjs"
  );
  const packagingScript = fs.readFileSync(packagingScriptPath, "utf8");

  assert(
    packagingScript.includes('set "DIALOG_TITLE=MSCQR Connector Setup"'),
    "Windows installer should define a dialog title"
  );
  assert(
    packagingScript.includes(
      'set "DIALOG_MESSAGE=MSCQR Connector setup completed successfully. Return to MSCQR and click Check again."'
    ),
    "Windows installer should show a success dialog"
  );
  assert(
    packagingScript.includes(
      'set "DIALOG_MESSAGE=MSCQR Connector setup did not complete. Review the Command Prompt window for the error details and try again."'
    ),
    "Windows installer should show a failure dialog"
  );
  assert(
    packagingScript.includes("[System.Windows.Forms.MessageBox]::Show"),
    "Windows installer should invoke a Windows message box"
  );
  assert(
    packagingScript.includes('Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup'),
    "Windows installer should register a per-user Startup entry"
  );
  assert(
    packagingScript.includes("Existing scheduled task could not be removed without elevation"),
    "Windows installer should tolerate legacy scheduled task cleanup failures"
  );

  console.log("windows connector installer script tests passed");
};

run();
