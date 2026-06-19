# Printer Trust Mode

## Launch trust contract

MSCQR launch printing uses signed connector attestation as the default secure trust mode. Connector `2026.6.16` signs heartbeat and action payloads with enrolled connector key material; it does not present a TLS client certificate.

Launch production config:

```env
PRINT_AGENT_REQUIRE_SIGNATURE=true
PRINT_AGENT_REQUIRE_MTLS=false
PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS=
```

In this mode, physical printing is eligible only when the backend verifies a fresh signed connector heartbeat against the enrolled public key and the server-side registration. The trust decision binds:

- authenticated manufacturer user scope and tenant fields stored on the registration
- agent registration ID
- agent ID
- device fingerprint
- selected printer ID/name from the current heartbeat state
- connector version/build/protocol/capabilities recorded with the heartbeat
- heartbeat nonce
- heartbeat issued-at timestamp
- freshness window
- enrolled public key and heartbeat signature

Browser/frontend state is never sufficient to mark a printer trusted or labels printed.

## What "mTLS client certificate fingerprint header missing" means

Optional strict mTLS mode expects a trusted reverse proxy to validate a connector client TLS certificate and forward its fingerprint in one of these headers:

- `x-client-cert-fingerprint`
- `x-ssl-client-fingerprint`

If `PRINT_AGENT_REQUIRE_MTLS=true` and that header is missing from a trusted proxy path, MSCQR blocks secure printing instead of marking the helper trusted. If `PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS` is empty, MSCQR ignores all fingerprint headers, including browser-supplied spoof attempts.

There is currently no repository evidence that production CloudFront, ALB, or nginx injects these fingerprint headers. Do not claim strict mTLS is active until connector client certificate provisioning and trusted proxy header injection are both deployed and validated.

## Signed attestation mode

```env
PRINT_AGENT_REQUIRE_SIGNATURE=true
PRINT_AGENT_REQUIRE_MTLS=false
PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS=
```

This is the launch-ready mode for connector `2026.6.16`. No connector bump is required for this trust model because the existing connector already supplies signed heartbeat and action payloads. No proxy mTLS change is required for this launch mode.

Failure behavior:

- missing/stale/invalid signature: blocked
- wrong agent ID, device fingerprint, registration, printer, or key: blocked
- compatibility/degraded storage fallback: diagnostics only, not print eligible
- helper visible but not cryptographically trusted: blocked
- stale connector action claim/ack/confirm: blocked with `PRINTER_ATTESTATION_STALE`

## Current limitation

The current released printer helper signs requests, but it does not yet present a client TLS certificate on its outbound HTTPS requests.

That means:

- You can run strong signed trust today.
- You cannot complete full end-to-end mTLS trust just by editing nginx.
- nginx can be prepared for mTLS header forwarding, but the helper still needs a future implementation pass to present the client certificate.

## Strict mTLS future mode

Use this only when the printer helper has been upgraded to send a client certificate and the reverse proxy is configured as a trusted mTLS header source.

### 1. Create a private CA

Create:

- one CA certificate for printer-helper client certificates
- one client certificate and key for each printer-helper workstation

Store them outside the repo.

### 2. Mount the CA into the frontend nginx container

Place the CA PEM somewhere on the host, for example:

```bash
/opt/mscqr/certs/printer-helper-ca.pem
```

Mount it into nginx in `docker-compose.yml`, for example:

```yaml
frontend:
  volumes:
    - /opt/mscqr/certs/printer-helper-ca.pem:/etc/nginx/mtls/printer-helper-ca.pem:ro
```

### 3. Add mTLS verification for helper-only API routes

In `nginx.https.conf`, add a dedicated location block before the generic `/api/` block for the printer-helper routes:

```nginx
  location ~ ^/api/(manufacturer/printer-agent/heartbeat|printer-agent/local/) {
    ssl_client_certificate /etc/nginx/mtls/printer-helper-ca.pem;
    ssl_verify_client on;

    proxy_pass http://backend:4000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Origin "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_read_timeout 300s;
  }
```

Configure the backend to trust only that proxy address for mTLS fingerprint headers:

```env
PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS=10.0.12.34
```

Do not include browser/client IP ranges here. The backend ignores `x-client-cert-fingerprint` and `x-ssl-client-fingerprint` unless the request is seen from one of these trusted proxy IPs.

If your edge uses a different header name, MSCQR also accepts:

```nginx
proxy_set_header X-SSL-Client-Fingerprint $ssl_client_fingerprint;
```

### 4. Configure the printer helper to present its client certificate

This is the missing piece in the current released helper.

The helper must be updated so its outbound HTTPS client uses:

- the workstation client certificate
- the workstation private key
- the public CA chain needed by the server

Without that step, nginx will never see a client certificate to validate, so it cannot set the fingerprint header.

### 5. Turn strict mode on

After nginx is validating helper certificates and forwarding the fingerprint header, set:

```env
PRINT_AGENT_REQUIRE_MTLS=true
PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS=<trusted-proxy-private-ip>
```

Then recreate `frontend`, `backend`, and `worker`.

### 6. Check the result

Success looks like this:

- printer heartbeat status reports `trustMode=STRICT_MTLS`
- audit history stops showing the missing-header reason
- the mTLS fingerprint appears only when the request source is a trusted proxy
- browser-supplied fingerprint headers remain ignored

## Current recommendation

For the current production build, keep:

```env
PRINT_AGENT_REQUIRE_SIGNATURE=true
PRINT_AGENT_REQUIRE_MTLS=false
PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS=
```

Rely on signed connector attestation until Gen-2 strict mTLS ships with connector client certificate provisioning and trusted proxy fingerprint injection.
