import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const createPrintJob: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const downloadPrintJobPack: (_req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const issueDirectPrintTokens: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const resolveDirectPrintToken: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const confirmPrintJob: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=printJobController.d.ts.map