import { Response } from "express";
import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
export declare const scanToken: (req: CustomerVerifyRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=scanController.d.ts.map