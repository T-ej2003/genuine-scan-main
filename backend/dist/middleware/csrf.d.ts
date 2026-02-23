import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";
export declare const requireCsrf: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
//# sourceMappingURL=csrf.d.ts.map