# MSCQR Connector Release Notes

LEGAL REVIEW REQUIRED BEFORE EXTERNAL PRODUCTION RELEASE

Version 2026.6.16 adds the local `/wake` endpoint and immediate direct-print worker wake behavior for user-initiated print jobs. The connector still falls back to bounded polling/backoff, respects backend rate limiting, and only backend/connector physical print confirmation can advance print lifecycle state.

Version 2026.6.11 adds transport-aware printer diagnostics, connector capability reporting, Windows queue inspection, TCP port inspection, RAW TCP diagnostics, USB Zebra spooler support, stuck-job status support, and explicit setup-test-label support.

Production printing remains blocked until the connector version, connector capabilities, printer route readiness, and setup-test-label proof all satisfy MSCQR safety policy.
