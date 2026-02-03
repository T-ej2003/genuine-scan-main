import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const createQrAllocationRequest: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getQrAllocationRequests: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const approveQrAllocationRequest: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const rejectQrAllocationRequest: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=qrRequestController.d.ts.map