import type { Request, RequestHandler } from "express";
import { isIP } from "node:net";
import proxyaddr from "proxy-addr";

type ClientIpTrustConfig =
  | { mode: "direct" }
  | { mode: "nginx"; trustedNginx: (address: string) => boolean }
  | { mode: "cloudfront-alb"; trustedAlb: (address: string) => boolean; trustedCloudFront: (address: string) => boolean }
  | { mode: "cloudfront-alb-nginx"; trustedNginx: (address: string) => boolean; trustedAlb: (address: string) => boolean; trustedCloudFront: (address: string) => boolean };

const normalizeIp = (value: string) => value.trim().replace(/^::ffff:/i, "");
const isIp = (value: string) => isIP(value) !== 0;

const configuredCidrs = (key: string) => String(process.env[key] || "").split(",").map((value) => value.trim()).filter(Boolean);

export const getClientIpTrustConfig = (): ClientIpTrustConfig => {
  const mode = String(process.env.CLIENT_IP_TRUST_MODE || (process.env.NODE_ENV === "production" ? "cloudfront-alb" : "direct")).trim().toLowerCase();
  if (mode === "direct") return { mode };
  if (mode !== "nginx" && mode !== "cloudfront-alb" && mode !== "cloudfront-alb-nginx") throw new Error("CLIENT_IP_TRUST_MODE must be direct, nginx, cloudfront-alb, or cloudfront-alb-nginx");
  const albCidrs = configuredCidrs("CLIENT_IP_TRUSTED_ALB_CIDRS");
  const cloudFrontCidrs = configuredCidrs("CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS");
  const nginxCidrs = configuredCidrs("CLIENT_IP_TRUSTED_NGINX_CIDRS");
  if ((mode === "nginx" && !nginxCidrs.length) || (mode !== "nginx" && (!albCidrs.length || !cloudFrontCidrs.length || (mode === "cloudfront-alb-nginx" && !nginxCidrs.length)))) {
    throw new Error(`${mode} client IP trust requires reviewed proxy CIDRs`);
  }
  try {
    if (mode === "nginx") return { mode, trustedNginx: proxyaddr.compile(nginxCidrs) };
    const trustedAlb = proxyaddr.compile(albCidrs);
    const trustedCloudFront = proxyaddr.compile(cloudFrontCidrs);
    if (mode === "cloudfront-alb") return { mode, trustedAlb, trustedCloudFront };
    return { mode, trustedNginx: proxyaddr.compile(nginxCidrs), trustedAlb, trustedCloudFront };
  } catch {
    throw new Error("client IP trusted proxy CIDRs are invalid");
  }
};

export const resolveClientIp = (req: Pick<Request, "get" | "socket">, config = getClientIpTrustConfig()) => {
  const socketIp = normalizeIp(String(req.socket?.remoteAddress || ""));
  if (!isIp(socketIp)) throw new Error("CLIENT_IP_SOCKET_INVALID");
  if (config.mode === "direct") return socketIp;

  const hops = String(req.get("x-forwarded-for") || "").split(",").map(normalizeIp).filter(Boolean);
  if (config.mode === "nginx") {
    if (!config.trustedNginx(socketIp) || hops.length !== 1 || !isIp(hops[0])) throw new Error("CLIENT_IP_PROXY_CHAIN_DENIED");
    return hops[0];
  }
  const albIp = config.mode === "cloudfront-alb-nginx" ? hops.at(-1) || "" : socketIp;
  const cloudFrontIp = config.mode === "cloudfront-alb-nginx" ? hops.at(-2) || "" : hops.at(-1) || "";
  const viewerIp = config.mode === "cloudfront-alb-nginx" ? hops.at(-3) || "" : hops.at(-2) || "";
  const trustedSocket = config.mode === "cloudfront-alb-nginx" ? config.trustedNginx(socketIp) : config.trustedAlb(socketIp);
  if (!trustedSocket || !isIp(albIp) || !config.trustedAlb(albIp) || !isIp(cloudFrontIp) || !config.trustedCloudFront(cloudFrontIp) || !isIp(viewerIp)) {
    throw new Error("CLIENT_IP_PROXY_CHAIN_DENIED");
  }
  return viewerIp;
};

const isLoopback = (address: string) => address === "127.0.0.1" || address === "::1";

export const trustedClientIpMiddleware = (config = getClientIpTrustConfig()): RequestHandler => (req, res, next) => {
  try {
    const socketIp = normalizeIp(String(req.socket?.remoteAddress || ""));
    const trustedLivenessPeer = isLoopback(socketIp) || ((config.mode === "cloudfront-alb" || config.mode === "cloudfront-alb-nginx") && config.trustedAlb(socketIp));
    const clientIp = req.path === "/health/live" && trustedLivenessPeer ? socketIp : resolveClientIp(req, config);
    Object.defineProperty(req, "ip", { configurable: true, enumerable: true, value: clientIp });
    next();
  } catch {
    res.status(400).json({ success: false, error: "Invalid proxy client identity" });
  }
};
