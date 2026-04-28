# Mock Zebra Printer

Run the mock printer and control panel with:

```bash
npm run mock:printer
```

From the `backend/` directory.

Defaults:

- Raw printer socket: `9100`
- HTTP control panel: `3001`

Useful endpoints:

- `GET /status`
- `GET /state/ready`
- `GET /state/paper-out`
- `GET /state/head-open`
- `GET /state/offline`

Remote backend note:

- `NETWORK_DIRECT` connections are opened by the backend server.
- If your backend runs in Docker Compose on Lightsail, register the printer host as `mock-printer` and port `9100`.
- If your backend runs directly on the Lightsail host with PM2/systemd, register `127.0.0.1` and port `9100` only when the mock printer is running on that same host.
