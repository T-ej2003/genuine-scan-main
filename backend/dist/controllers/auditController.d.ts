import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const getLogs: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const exportLogsCsv: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const streamLogs: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>> | undefined>;
//# sourceMappingURL=auditController.d.ts.map