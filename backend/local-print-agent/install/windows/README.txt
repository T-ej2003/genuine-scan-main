MSCQR Connector for Windows
Version: __MSCQR_CONNECTOR_VERSION__

Use the governed signed Windows installer for installation and executable testing.
Unsigned inspection ZIPs are not installable and are not production downloads.

Setup steps:
1. Obtain the approved signed Windows installer through the governed release process.
2. Run that installer on the Windows computer connected to the printer.
3. Setup runs mandatory initialization and verification automatically, including silent mode.
4. Upgrades require authenticated maintenance authorization and reconciliation before replacing the runtime.
5. If the printer is not ready yet, the connector stays installed and MSCQR Printer Setup opens so you can finish the OS-side checks.
6. If Windows Smart App Control blocks the signed installer, stop and contact MSCQR support. Do not disable policy or change script execution requirements.

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
