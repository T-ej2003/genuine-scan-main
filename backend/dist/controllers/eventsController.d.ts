import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
/**
 * SSE stream for dashboard updates.
 * Use EventSource in frontend:
 *   new EventSource(`${API}/api/events/dashboard?token=${token}`)
 */
export declare const dashboardEvents: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>> | undefined>;
//# sourceMappingURL=eventsController.d.ts.map