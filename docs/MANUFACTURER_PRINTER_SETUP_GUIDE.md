# Manufacturer Printer Setup Guide

## Goal

Set up MSCQR printing so factory operators can print without starting technical services manually.

## Choose the right printer path

### `LOCAL_AGENT`

Choose this when the printer is installed on a workstation and depends on the local operating system.

Typical examples:

- USB printers
- driver-managed desktop printers
- printers using SBPL, ESC/POS, or vendor-specific spooler behavior

### `NETWORK_DIRECT`

Choose this when the printer is a raw LAN label printer with a fixed network path.

Use only when the printer supports one of:

- `ZPL`
- `TSPL`
- `EPL`
- `CPCL`

### `NETWORK_IPP`

Choose this when the printer is an AirPrint or IPP Everywhere device that accepts PDF jobs.

Use:

- `Backend direct` when the MSCQR backend can safely reach the printer
- `Site gateway` when the printer stays inside a private manufacturer LAN

## Workstation connector rollout

For `LOCAL_AGENT` and site-gateway deployments:

1. Package the MSCQR Workstation Connector as a signed installer or IT-managed rollout.
2. Install it once on the target workstation.
3. Confirm it auto-starts at login.
4. Confirm the operating system already shows the printer.
5. Open `Printer Diagnostics` in MSCQR and verify readiness.

Do not ask end users to run terminal commands to print.

## Register a raw LAN printer

In `Printer Diagnostics`:

1. Add a managed printer profile.
2. Choose `NETWORK_DIRECT`.
3. Enter the approved IP address or host and TCP port.
4. Select the printer language.
5. Save and run `Test`.
6. Use the profile only after it reports `READY`.

## Register an AirPrint / IPP printer

In `Printer Diagnostics`:

1. Add a managed printer profile.
2. Choose `NETWORK_IPP`.
3. Enter either the printer URI or the host, port, and resource path.
4. Enable TLS when the printer supports IPPS.
5. Choose the delivery mode.
6. Save and run `Test`.

Preferred defaults:

- port `631`
- resource path `/ipp/print`
- `ipps://` when supported

## Configure a site gateway

Use this only when the printer is on a private LAN that the MSCQR backend cannot directly reach.

1. Register the printer as `NETWORK_IPP`.
2. Set delivery mode to `Site gateway`.
3. Save the profile and copy the one-time gateway bootstrap secret.
4. Provision the following values into the workstation connector `agent.env` file:

```dotenv
PRINT_GATEWAY_BACKEND_URL=https://your-mscqr-host/api
PRINT_GATEWAY_ID=<gateway-id>
PRINT_GATEWAY_SECRET=<one-time-bootstrap-secret>
```

5. Restart or reinstall the connector through your signed installer or IT automation.
6. Return to `Printer Diagnostics` and verify the profile changes to `Site gateway online`.

## Print-job validation checklist

Before live printing:

1. The printer profile is `READY`.
2. The correct dispatch mode appears in the print dialog.
3. The workstation or gateway is online.
4. A test job succeeds.
5. The printed count updates in MSCQR.

## Escalation checklist

If printing fails:

1. Open `Printer Diagnostics`.
2. Copy the diagnostic snapshot.
3. Note the printer profile name, job number, and timestamp.
4. Confirm whether the issue is local workstation, network reachability, IPP validation, or gateway heartbeat.
