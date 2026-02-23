import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const listIrIncidents: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const createIrIncident: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getIrIncident: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const patchIrIncident: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const addIrIncidentEvent: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const applyIrIncidentAction: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const sendIrIncidentCommunication: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=irIncidentController.d.ts.map