import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";

export const issueDirectPrintTokens = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Browser-mediated direct printing has been disabled. Create the print job and let the MSCQR connector claim work directly from the server.",
  });
};
