import { Router } from "express";
import { publicVerify } from "../controllers/publicController";

const router = Router();

// Legacy public aliases delegate to the canonical verification controller.
router.get("/verify/:code", publicVerify);
router.get("/verify", publicVerify);

export default router;
