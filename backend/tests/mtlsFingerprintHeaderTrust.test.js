const assert = require("assert");

const { getTrustedMtlsFingerprintHeader } = require("../dist/utils/mtlsFingerprintHeader");

const buildReq = ({ ip = "198.51.100.50", remoteAddress = ip, headers = {} } = {}) => ({
  ip,
  socket: { remoteAddress },
  get: (name) => headers[String(name).toLowerCase()] || "",
});

const originalTrustedProxies = process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS;

try {
  process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS = "10.0.0.10";
  assert.strictEqual(
    getTrustedMtlsFingerprintHeader(
      buildReq({
        ip: "198.51.100.50",
        headers: { "x-client-cert-fingerprint": "browser-spoofed-fingerprint" },
      })
    ),
    null,
    "untrusted requests must not be allowed to self-assert an mTLS fingerprint"
  );

  assert.strictEqual(
    getTrustedMtlsFingerprintHeader(
      buildReq({
        ip: "10.0.0.10",
        headers: { "x-client-cert-fingerprint": "trusted-proxy-fingerprint" },
      })
    ),
    "trusted-proxy-fingerprint",
    "trusted proxy requests should pass the client certificate fingerprint through"
  );

  process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS = "";
  assert.strictEqual(
    getTrustedMtlsFingerprintHeader(
      buildReq({
        ip: "10.0.0.10",
        headers: {
          "x-client-cert-fingerprint": "ignored-client-fingerprint",
          "x-ssl-client-fingerprint": "ignored-ssl-fingerprint",
        },
      })
    ),
    null,
    "empty PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS must ignore all client-supplied fingerprint headers"
  );

  console.log("mTLS fingerprint header trust tests passed");
} finally {
  if (originalTrustedProxies === undefined) {
    delete process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS;
  } else {
    process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS = originalTrustedProxies;
  }
}
