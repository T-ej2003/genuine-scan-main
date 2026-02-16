import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const listIrAlerts: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const patchIrAlert: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=irAlertController.d.ts.map