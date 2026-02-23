import type { Request, Response } from "express";
export declare const issueCustomerSession: (res: Response, user: {
    id: string;
    email: string;
    name?: string | null;
    provider?: string | null;
}) => void;
export declare const clearCustomerSession: (res: Response) => void;
export declare const readCustomerSession: (req: Request) => {
    customerUserId: string;
    email: string;
    name?: string | null;
    provider?: string | null;
} | null;
export declare const ensureAnonVisitorId: (req: Request, res: Response) => string;
export declare const getVisitorFingerprint: (req: Request) => string | null;
export declare const getHashedIp: (req: Request) => string | null;
export declare const getCustomerIdentityContext: (req: Request, res: Response) => {
    customerUserId: string | null;
    customer: {
        customerUserId: string;
        email: string;
        name?: string | null;
        provider?: string | null;
    } | null;
    anonVisitorId: string;
    visitorFingerprint: string | null;
    ipHash: string | null;
};
//# sourceMappingURL=customerSessionService.d.ts.map