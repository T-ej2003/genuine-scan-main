# Persistent Printer WebSocket Handshake Diagnostics

## Production Evidence

- Windows connector `2026.6.26` is locally healthy, has backend configuration, has a selected Zebra printer, and advertises `supportsPersistentPrintSession=true`.
- The connector reports `websocket.connected=false` with `Persistent session upgrade rejected on /api/printer-agent/session with HTTP 403.`
- Manual WebSocket probes from macOS and Windows to `https://www.mscqr.com/api/printer-agent/session` return `101 Switching Protocols`.
- Manual probes to the direct ALB also return `101 Switching Protocols`.
- Backend application logs do not show `printer_session_rejected` for the connector attempts, which means the installed connector is rejected before backend hello processing or outside the app-level session admission path.

## Change Summary

This branch adds handshake-level diagnostics without weakening printer trust:

- Backend logs `printer_session_upgrade_seen` before `wss.handleUpgrade` for supported session paths.
- Backend logs `printer_session_upgrade_unhandled_path` and `printer_session_upgrade_handle_error` for session-shaped upgrade failures.
- Connector logs the resolved WebSocket origin/path, backend origin, selected printer, hashed connector identity, build version, persistent-session capability, and proxy environment variable presence.
- Connector `unexpected-response` handling records HTTP status, safe whitelisted response headers, a redacted body preview, and a richer reject reason code.

## Safety Notes

- No REST production print fallback was added.
- No signature, trust, or printer eligibility checks were bypassed.
- Logs must not include private keys, raw public keys, signatures, cookies, CSRF values, tokens, full IP addresses, or full signed URLs.
- The backend upgrade path still performs trust admission only after the WebSocket upgrade and signed connector hello.
