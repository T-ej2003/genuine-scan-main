import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";

export const reportDirectPrintFailure = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Browser-mediated direct printing has been disabled. The MSCQR connector now reports print failures directly to the server.",
  });
};
