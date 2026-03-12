# MSCQR Printing Architecture Standard

## Purpose

This document defines the production printing standard for MSCQR. The goal is simple:

- no manual "run the agent" step for end users
- no browser-only local printer hacks
- no insecure exposure of printer ports to the public internet
- one secure print workflow across workstation, LAN, and private-site printers

## Why pure browser local-printer printing is intentionally not supported

Browsers do not expose a production-safe, silent, printer-aware local printing API for this use case.

- `window.print()` opens the browser print dialog and cannot enforce secure printer selection, quiet background dispatch, or device capability checks.
- Browser hardware APIs such as WebUSB, WebSerial, and WebHID are not the right production foundation for mixed printer fleets. They require per-browser support, explicit user permissions, and device-specific handling.
- A web app cannot reliably inspect the operating system printer list, validate spooler readiness, or manage secure retries by itself.

For that reason, MSCQR does not treat pure browser local-printer printing as a supported production path.

## Approved production patterns

### 1. `LOCAL_AGENT`

Use this for:

- USB printers
- driver-dependent printers
- workstation-managed Wi-Fi or office printers
- printer languages that still depend on the OS driver path

Operational standard:

- install the signed MSCQR Workstation Connector once
- auto-start at login
- keep it running in the background
- let the browser communicate only with the trusted local listener

### 2. `NETWORK_DIRECT`

Use this for:

- raw LAN label printers
- stable IP/port printer targets
- approved command languages only

Current supported command languages:

- `ZPL`
- `TSPL`
- `EPL`
- `CPCL`

This mode is intentionally restricted to registered printer profiles. Freeform host entry during print is not allowed.

### 3. `NETWORK_IPP`

Use this for:

- AirPrint printers
- IPP Everywhere printers
- office printers that accept PDF over IPP/IPPS

Operational standard:

- prefer `ipps://` when the printer supports TLS
- validate the printer URI before dispatch
- submit standards-based PDF jobs over IPP/IPPS
- do not downgrade AirPrint printers to raw port `9100`

## Private-LAN site gateway standard

When the backend cannot directly reach a manufacturer-site printer, MSCQR uses a site gateway pattern:

- the installed workstation connector keeps an outbound authenticated connection to MSCQR
- MSCQR never requires inbound firewall holes to reach the site
- the gateway claims approved print jobs and dispatches them locally
- gateway credentials are provisioned once through the printer profile bootstrap flow

This is the approved pattern for private manufacturer networks.

## Dispatch routing standard

MSCQR routes printers by capability:

1. `LOCAL_AGENT` for workstation-managed printers
2. `NETWORK_DIRECT` for raw ZPL/TSPL/EPL/CPCL label printers
3. `NETWORK_IPP` for AirPrint / IPP Everywhere printers

## Security requirements

- approved labels remain server-controlled
- print locks and render-token workflows remain intact
- printer targets must be registered, validated, and auditable
- raw printer ports are never exposed publicly
- gateway credentials are scoped to registered printers

## Operational guidance

- Fleet rollout should use signed installers or MDM, not terminal instructions for operators.
- For workstation printing, the OS must already see the printer before MSCQR can use it.
- For `NETWORK_IPP`, validate PDF support and URI reachability before the first live job.
- For private-LAN sites, prefer `NETWORK_IPP` with site gateway over ad hoc workstation browser flows.
- For Docker deployments on AWS Lightsail, standard operations are `docker compose build`, `docker compose run --rm backend npx prisma migrate deploy`, and `docker compose up -d --force-recreate`, not ad hoc `systemctl` restarts.
