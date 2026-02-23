import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const createLicensee: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getLicensees: (_req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getLicensee: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const updateLicensee: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const deleteLicensee: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const resendLicenseeAdminInvite: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const exportLicenseesCsv: (_req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=licenseeController.d.ts.map