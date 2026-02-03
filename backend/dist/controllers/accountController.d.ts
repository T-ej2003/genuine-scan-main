import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const updateMyProfile: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const changeMyPassword: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=accountController.d.ts.map