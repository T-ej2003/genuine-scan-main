import type { Request, RequestHandler } from "express";
import { isIP } from "node:net";

const proxyaddr: { compile(values: string[]): (address: string) => boolean } = require("proxy-addr");

type ClientIpTrustConfig =
  | { mode: "direct" }
  | { mode: "cloudfront-alb"; trustedAlb: (address: string) => boolean; trustedCloudFront: (address: string) => boolean };

const normalizeIp = (value: string) => value.trim().replace(/^::ffff:/i, "");
const isIp = (value: string) => isIP(value) !== 0;

const configuredCidrs = (key: string) => String(process.env[key] || "").split(",").map((value) => value.trim()).filter(Boolean);

export const getClientIpTrustConfig = (): ClientIpTrustConfig => {
  const mode = String(process.env.CLIENT_IP_TRUST_MODE || (process.env.NODE_ENV === "production" ? "cloudfront-alb" : "direct")).trim().toLowerCase();
  if (mode === "direct") return { mode };
  if (mode !== "cloudfront-alb") throw new Error("CLIENT_IP_TRUST_MODE must be direct or cloudfront-alb");
  const albCidrs = configuredCidrs("CLIENT_IP_TRUSTED_ALB_CIDRS");
  const cloudFrontCidrs = configuredCidrs("CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS");
  if (!albCidrs.length || !cloudFrontCidrs.length) throw new Error("cloudfront-alb client IP trust requires CLIENT_IP_TRUSTED_ALB_CIDRS and CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS");
  try {
    return { mode, trustedAlb: proxyaddr.compile(albCidrs), trustedCloudFront: proxyaddr.compile(cloudFrontCidrs) };
  } catch {
    throw new Error("client IP trusted proxy CIDRs are invalid");
  }
};

export const resolveClientIp = (req: Pick<Request, "get" | "socket">, config = getClientIpTrustConfig()) => {
  const socketIp = normalizeIp(String(req.socket?.remoteAddress || ""));
  if (!isIp(socketIp)) throw new Error("CLIENT_IP_SOCKET_INVALID");
  if (config.mode === "direct") return socketIp;

  const hops = String(req.get("x-forwarded-for") || "").split(",").map(normalizeIp).filter(Boolean);
  const cloudFrontIp = hops.at(-1) || "";
  const viewerIp = hops.at(-2) || "";
  if (!config.trustedAlb(socketIp) || !isIp(cloudFrontIp) || !config.trustedCloudFront(cloudFrontIp) || !isIp(viewerIp)) {
    throw new Error("CLIENT_IP_PROXY_CHAIN_DENIED");
  }
  return viewerIp;
};

export const trustedClientIpMiddleware = (config = getClientIpTrustConfig()): RequestHandler => (req, res, next) => {
  try {
    Object.defineProperty(req, "ip", { configurable: true, enumerable: true, value: resolveClientIp(req, config) });
    next();
  } catch {
    res.status(400).json({ success: false, error: "Invalid proxy client identity" });
  }
};
