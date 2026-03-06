import { Request, Response } from "express";
import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
export declare const requestCustomerEmailOtp: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const verifyCustomerEmailOtp: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const verifyQRCode: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const claimProductOwnership: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const linkDeviceClaimToCustomer: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const createOwnershipTransfer: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const cancelOwnershipTransfer: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const acceptOwnershipTransfer: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const reportFraud: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const submitProductFeedback: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=verifyController.d.ts.map