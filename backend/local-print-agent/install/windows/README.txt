MSCQR Connector for Windows
Version: __MSCQR_CONNECTOR_VERSION__

Setup steps:
1. Extract this ZIP to a normal folder on the Windows computer that is connected to the printer.
2. Do not run the installer from inside the ZIP preview in File Explorer.
3. Double-click "Install Connector.cmd" from the extracted folder.
4. The installer will verify that the connector started and check whether Windows is exposing a usable printer.
5. If the printer is not ready yet, the connector stays installed and MSCQR Printer Setup opens so you can finish the OS-side checks.
6. If Windows Smart App Control blocks "Install Connector.cmd", stop there and ask your admin for the signed Windows installer instead of retrying the blocked file.

What this does:
- installs the MSCQR Connector for the signed-in Windows user
- starts the connector immediately
- configures it to start automatically at every sign-in
- verifies local printer readiness before claiming success

What the result means:
- Success: connector installed, local agent reachable, and a usable online printer was verified
- Needs attention: connector installed and running, but Windows is not currently exposing a usable printer
- Failure: install or agent startup did not complete; review the local log and try again

Printer Setup URL:
__MSCQR_WEB_APP_BASE_URL__/printer-diagnostics

Optional advanced configuration:
- %LOCALAPPDATA%\MSCQR\local-print-agent\agent.env

Local logs:
- %LOCALAPPDATA%\MSCQR\local-print-agent\logs\agent.log
