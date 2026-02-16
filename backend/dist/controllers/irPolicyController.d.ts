import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const listIrPolicies: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const createIrPolicy: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const patchIrPolicy: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=irPolicyController.d.ts.map