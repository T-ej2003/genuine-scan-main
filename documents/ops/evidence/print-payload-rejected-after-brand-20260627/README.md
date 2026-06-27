# Print payload rejected after brand asset deployment - 2026-06-27

After deploying official brand assets, connector worked and local helper responded, but print runs failed before physical printing.

Observed UI:
- Print job created
- UI showed printing in progress
- No labels physically printed
- Recent print runs showed partially completed / failed
- Error: Payload rejected before print: generated Zebra ZPL looks unsafe for this profile.

Likely area:
- Backend ZPL generation introduced branded wordmark graphic.
- Connector/safety profile rejected generated Zebra ZPL before print.
- This makes the UI misleading because the print run appears started even though no physical print occurred.

Immediate mitigation:
- Roll backend service back to last stable print backend task definition.
- Keep frontend deployment separate if needed.

Required follow-up:
- Harden secure printing state machine and UI.
- Add preflight ZPL safety validation before creating/starting print job.
- Do not show "printing in progress" until connector has accepted the payload.
- Make printer errors actionable and manufacturer-safe.
- Validate Zebra ZPL graphic payload on real hardware before production.
