MSCQR Connector for Windows
Version: __MSCQR_CONNECTOR_VERSION__

This ZIP is an unsigned Windows test package for internal validation only.
Customer-facing rollout should use the signed Windows installer once it is published.

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

Fresh setup exit codes: 0 means installed and printer ready; 10 means installed
and runtime verified but printer setup needs attention. All other nonzero codes
mean failure. Signed Setup accepts 10 for fresh installation, logs a warning in
silent mode and preserves install-result.json; 10 is not printer certification.
Upgrade phases require 0 plus authenticated maintenance and independent runtime,
identity and startup verification. Fresh-install partial success cannot commit
an upgrade or release its maintenance fence.

Printer Setup URL:
__MSCQR_WEB_APP_BASE_URL__/printer-diagnostics

Optional advanced configuration:
- %LOCALAPPDATA%\MSCQR\local-print-agent\agent.env

Local logs:
- %LOCALAPPDATA%\MSCQR\local-print-agent\logs\agent.log
