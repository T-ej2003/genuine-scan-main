import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";

export const resolveDirectPrintToken = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Browser-mediated direct printing has been disabled. The MSCQR connector now claims approved labels directly from the server.",
  });
};
