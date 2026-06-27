# MSCQR printer WebSocket recovery evidence - 2026-06-26

## Result

Persistent printer WebSocket is working through CloudFront/WAF to ECS backend.

## Validation

- ECS backend service stable on task definition mscqr-backend:40.
- Desired tasks: 2.
- Running tasks: 2.
- Failed tasks: 0.
- Backend image tag: a5b1036fd41764572f95866bdc32f96ca4feb7ef.
- ECR image manifest includes linux/amd64.
- CloudFront/WAF allows GET websocket upgrades for /api/printer-agent/session.
- Backend logs show printer_session_connected.
- Backend logs show printer_session_socket_ready.
- Backend logs show repeated printer_session_heartbeat.
- Backend logs show printer_session_work_sent.
- Backend logs show printer_session_chunk_ack.
- Windows connector status showed websocket.connected=true with registrationId and sessionId.

## Root cause

CloudFront WAF was blocking WebSocket upgrade requests from the Windows connector when the request had no User-Agent header. Raw WebSocket upgrades with normal curl User-Agent passed, but empty User-Agent requests were blocked before backend admission. Adding a narrow WAF allow rule for GET websocket upgrades on /api/printer-agent/session fixed the transport path without bypassing backend signed-attestation trust checks.

## Security posture

The WAF allow rule only allows the WebSocket upgrade to reach the backend. Backend admission still requires trusted printer registration, valid signed attestation, selected printer match, connector version acceptance, and persistent-session capability.

## Follow-up

The running ECS image is correct, but backend log release labels still show mscqr-backend@1.0.0+ba63f23dd20d. Verify and repair release label injection separately.
