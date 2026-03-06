import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const getScanLogs: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getBatchSummary: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getQrTrackingAnalyticsController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=qrLogController.d.ts.map