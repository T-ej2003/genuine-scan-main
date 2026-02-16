import { Request, Response } from "express";
export declare const getCurrentCustomer: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const googleCustomerAuth: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const requestCustomerOtp: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const verifyCustomerOtp: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const logoutCustomer: (_req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=customerAuthController.d.ts.map