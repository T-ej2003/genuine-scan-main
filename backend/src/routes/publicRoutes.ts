import { Router } from "express";
import { publicVerify } from "../controllers/publicController";

const router = Router();

// Support both /public/verify/:code and /public/verify?code=
router.get("/verify/:code", publicVerify);
router.get("/verify", publicVerify);

// Report endpoint can be added once you share DB schema for storing reports
export default router;

