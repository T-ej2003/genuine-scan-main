import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
export declare const createUser: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getUsers: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getManufacturers: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const updateUser: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const deleteUser: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const deactivateManufacturer: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const restoreManufacturer: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const hardDeleteManufacturer: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
//# sourceMappingURL=userController.d.ts.map