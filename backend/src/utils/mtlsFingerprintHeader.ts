import type { Request } from "express";

type MtlsHeaderRequest = Pick<Request, "ip" | "get"> & {
  socket?: {
    remoteAddress?: string | null;
  };
};

const mtlsTrustedProxyValues = () =>
  String(process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

const normalizeIp = (value?: string | null) =>
  String(value || "")
    .trim()
    .replace(/^::ffff:/, "");

export const isTrustedMtlsProxyRequest = (req: MtlsHeaderRequest) => {
  const allowed = mtlsTrustedProxyValues();
  if (allowed.length === 0) return false;
  // Only the transport peer can establish proxy authority; forwarded headers
  // (including req.ip) are not evidence of who supplied the certificate header.
  const peer = normalizeIp(req.socket?.remoteAddress);
  return Boolean(peer) && allowed.some((value) => peer === normalizeIp(value));
};

export const getTrustedMtlsFingerprintHeader = (req: MtlsHeaderRequest) => {
  const header = String(req.get("x-client-cert-fingerprint") || req.get("x-ssl-client-fingerprint") || "").trim();
  if (!header) return null;
  return isTrustedMtlsProxyRequest(req) ? header : null;
};
