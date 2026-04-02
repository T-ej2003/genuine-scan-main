import { Response } from "express";

import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
import { verifyQRCode } from "./verify/verificationHandlers";

export const scanToken = async (req: CustomerVerifyRequest, res: Response) => {
  return verifyQRCode(req, res);
};
