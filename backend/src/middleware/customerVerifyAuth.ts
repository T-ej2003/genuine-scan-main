import { NextFunction, Request, Response } from "express";

import {
  CustomerVerifyIdentity,
  verifyCustomerVerifyToken,
} from "../services/customerVerifyAuthService";

export interface CustomerVerifyRequest extends Request {
  customer?: CustomerVerifyIdentity;
}

const getBearerToken = (req: Request) => {
  const authHeader = String(req.headers.authorization || "").trim();
  if (!authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim() || null;
};

export const optionalCustomerVerifyAuth = (req: CustomerVerifyRequest, _res: Response, next: NextFunction) => {
  const token = getBearerToken(req);
  if (!token) {
    return next();
  }

  try {
    req.customer = verifyCustomerVerifyToken(token);
  } catch {
    // Ignore invalid customer token for optional auth routes.
  }

  return next();
};

export const requireCustomerVerifyAuth = (req: CustomerVerifyRequest, res: Response, next: NextFunction) => {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Customer authentication required",
    });
  }

  try {
    req.customer = verifyCustomerVerifyToken(token);
    return next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired customer session",
    });
  }
};
