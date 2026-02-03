import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const streamAuditLogs: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>> | undefined>;
//# sourceMappingURL=auditStreamController.d.ts.map