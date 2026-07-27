import { Router } from "express";
import { publicVerify } from "../controllers/publicController";

const router = Router();

// Quarantined legacy router: no production entry point imports or mounts this
// module. Canonical /api/verify routes and their limiters live in routes/index.
router.get("/verify/:code", publicVerify);
router.get("/verify", publicVerify);

export default router;
