import { Response } from "express";
import { auditStream } from "../events/auditStream";
import { AuthRequest } from "../middleware/auth";
import { UserRole } from "@prisma/client";

// SSE uses EventSource on browser which cannot send Authorization header.
// We'll accept token via query (?token=...) safely for localhost.
// If you want stricter security later, we can switch to cookie-based auth.

import jwt from "jsonwebtoken";
import { JWTPayload } from "../types";

function authenticateSSE(req: AuthRequest): JWTPayload | null {
  const token = (req.query.token as string | undefined) || "";
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
  } catch {
    return null;
  }
}

export const streamAuditLogs = async (req: AuthRequest, res: Response) => {
  const user = authenticateSSE(req);
  if (!user) return res.status(401).json({ success: false, error: "Unauthorized SSE" });

  // Visibility rule:
  // - SUPER_ADMIN: sees all
  // - LICENSEE_ADMIN: sees only their licensee (requires licenseeId stored on logs)
  // - MANUFACTURER: usually no access (you said controls yes all, but normally no)
  if (
    user.role !== UserRole.SUPER_ADMIN &&
    user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
    user.role !== UserRole.LICENSEE_ADMIN &&
    user.role !== UserRole.ORG_ADMIN
  ) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const heartbeat = setInterval(() => {
    res.write(`event: ping\ndata: {}\n\n`);
  }, 25000);

  const off = auditStream.onLog((evt) => {
    // tenant filter (only works well if AuditLog has licenseeId)
    if (user.role === UserRole.LICENSEE_ADMIN || user.role === UserRole.ORG_ADMIN) {
      if (!user.licenseeId) return;
      if ((evt.licenseeId || null) !== user.licenseeId) return;
    }

    res.write(`event: audit\ndata: ${JSON.stringify(evt)}\n\n`);
  });

  req.on("close", () => {
    clearInterval(heartbeat);
    off();
    res.end();
  });
};
