# MSCQR Printing Architecture Standard

## Purpose

This document defines the production printing standard for MSCQR. The goal is simple:

- no manual "run the agent" step for end users
- no browser-only local printer hacks
- no insecure exposure of printer ports to the public internet
- one secure print workflow across workstation, LAN, and private-site printers

## Current manufacturer printing and customer verification contract

As of 17 November 2026, the supported manufacturer integration is the MSCQR web application, the signed Windows Workstation Connector, and a USB or LAN printer. A signed per-item confirmation must commit in the backend before that exact QR becomes customer-verifiable. A sample scan, separate batch release, and independent post-print approval are not required for this customer-verification path.

`SITE_GATEWAY` remains available for existing installations while its consumers and retirement path are assessed. It is a legacy compatibility integration and a retirement candidate, not part of the new automatic customer-activation contract. Gateway confirmation uses a shared secret and caller-supplied details; it cannot create the signed per-item activation evidence required for customer verification. Do not infer that no installations use it or remove it without a separate compatibility review.

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
- distribute the connector through the in-app `Install Connector` page and versioned installer URLs

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

## Legacy private-LAN site gateway compatibility

Existing private-LAN installations may use a site gateway pattern:

- the installed legacy gateway process keeps an outbound authenticated connection to MSCQR
- MSCQR never requires inbound firewall holes to reach the site
- the gateway claims approved print jobs and dispatches them locally
- gateway credentials are provisioned once through the printer profile bootstrap flow

This path remains for compatibility. It is excluded from automatic customer activation, and new manufacturer printing should use the signed Windows connector.

PR #854 retains gateway claim, acknowledgement, confirmation, failure, and print-job state handling. A gateway confirmation still commits its `PrintItem` and marks the matching QR `PRINTED` when the QR belongs to that job and batch and is in an allowed pre-print state. The added QR linkage and state guard means an inconsistent or blocked legacy QR record is no longer marked `PRINTED` by gateway confirmation; it requires operator reconciliation. This is a compatibility impact of the security guard, not evidence of customer activation.

## Connector distribution standard

MSCQR now distributes the workstation connector through one product-safe path:

- invite email includes:
  the activation link
  and the `Install Connector` link
- the public `Install Connector` page offers the latest Mac and Windows packages
- versioned download URLs point to packaged artifacts stored under the connector release manifest
- the app help pages and manufacturer onboarding flow point to the same download page

This keeps manufacturer onboarding consistent across:

- onboarding email
- accept-invite page
- dashboard printer onboarding
- printer help documentation

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
- For private-LAN manufacturer sites, use the signed Windows connector for the supported customer-activation flow. Existing `SITE_GATEWAY` integrations require a separate retirement and migration review.
- For Docker deployments on AWS Lightsail, standard operations are `docker compose build`, `docker compose run --rm backend npx prisma migrate deploy`, and `docker compose --profile worker up -d --force-recreate` when that host intentionally owns the singleton worker, not ad hoc `systemctl` restarts.
