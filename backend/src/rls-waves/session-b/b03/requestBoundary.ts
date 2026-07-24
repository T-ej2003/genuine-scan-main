import type { AuthRequest } from "../../../middleware/auth";
import {
  createB03AuthenticatedFunctionBoundary,
  type B03AuthenticatedFunctionBoundary,
} from "./repositoryFunctions";

export const b03BoundaryForRequest = (
  req: AuthRequest,
  purpose: string
): B03AuthenticatedFunctionBoundary => {
  if (!req.user) throw new Error("B03 authenticated actor is required");
  return createB03AuthenticatedFunctionBoundary({
    claims: req.user,
    capability: String(req.databaseSessionCapability || ""),
    requestId: String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || ""),
    purpose,
  });
};
