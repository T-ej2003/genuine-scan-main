import { Request, Response } from "express";

import { verifyQRCode } from "./verifyController";

export const publicVerify = async (req: Request, res: Response) => {
  const code = String(req.params.code || req.query.code || "").trim();
  const delegatedReq = req as Request & { params: Record<string, unknown> };
  delegatedReq.params = {
    ...(req.params || {}),
    code,
  };
  return verifyQRCode(delegatedReq as any, res);
};
