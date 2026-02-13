import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const getTraceTimelineController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getBatchSlaAnalyticsController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getRiskAnalyticsController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getPolicyConfigController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const updatePolicyConfigController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getPolicyAlertsController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const acknowledgePolicyAlertController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const exportBatchAuditPackageController: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=tracePolicyController.d.ts.map