import { Request, Response, NextFunction } from "express";
import { JWTPayload } from "../types";
export interface AuthRequest extends Request {
    user?: JWTPayload;
    authMode?: "bearer" | "cookie";
}
export declare const authenticate: (req: AuthRequest, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
export declare const optionalAuth: (req: AuthRequest, _res: Response, next: NextFunction) => Promise<void>;
/**
 * SSE auth supports:
 * - ?token= (for EventSource)
 * - Authorization: Bearer (normal)
 * - Cookie access token (preferred; avoids putting tokens in URLs)
 */
export declare const authenticateSSE: (req: AuthRequest, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
//# sourceMappingURL=auth.d.ts.map