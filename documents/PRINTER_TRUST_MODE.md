# Printer Trust Mode

## What "mTLS client certificate fingerprint header missing" means

MSCQR has two printer trust layers:

1. The printer helper signs its requests with its enrolled key pair.
2. Optional strict mode also expects the reverse proxy to validate a client TLS certificate and forward its fingerprint in one of these headers:
   - `x-client-cert-fingerprint`
   - `x-ssl-client-fingerprint`

If `PRINT_AGENT_REQUIRE_MTLS=true` and that header is missing, MSCQR keeps printing available in recovery mode instead of marking the helper fully trusted.

## Fast production fix

If you are not actively running client-certificate mTLS for the printer helper yet, use:

```env
PRINT_AGENT_REQUIRE_MTLS=false
```

Then recreate `backend` and `worker`.

## Important current limitation

The current released printer helper signs requests, but it does not yet present a client TLS certificate on its outbound HTTPS requests.

That means:

- You can run strong signed trust today.
- You cannot complete full end-to-end mTLS trust just by editing nginx.
- nginx can be prepared for mTLS header forwarding, but the helper still needs a future implementation pass to present the client certificate.

## Strict-mode path for the current stack

Use this only when the printer helper has been upgraded to send a client certificate.

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
```

Then recreate `frontend`, `backend`, and `worker`.

### 6. Check the result

Success looks like this:

- printer heartbeat logs stop mentioning compatibility mode
- audit history stops showing the missing-header reason
- the printer status no longer shows recovery mode

## Current recommendation

For the current production build, keep:

```env
PRINT_AGENT_REQUIRE_MTLS=false
```

and rely on the signed helper identity path until the helper gains real client-certificate support.
