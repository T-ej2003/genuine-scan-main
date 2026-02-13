import { Request, Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const uploadIncidentReportPhotos: import("express").RequestHandler<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>>;
export declare const uploadIncidentEvidence: import("express").RequestHandler<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>>;
export declare const reportIncident: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const listIncidents: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getIncident: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const patchIncident: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const addIncidentEventNote: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const addIncidentEvidence: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const notifyIncidentCustomer: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const exportIncidentPdfHook: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const serveIncidentEvidenceFile: (req: AuthRequest, res: Response) => Promise<void | Response<any, Record<string, any>>>;
//# sourceMappingURL=incidentController.d.ts.map