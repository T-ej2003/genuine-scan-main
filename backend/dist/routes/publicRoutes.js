"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const publicController_1 = require("../controllers/publicController");
const router = (0, express_1.Router)();
// Support both /public/verify/:code and /public/verify?code=
router.get("/verify/:code", publicController_1.publicVerify);
router.get("/verify", publicController_1.publicVerify);
// Report endpoint can be added once you share DB schema for storing reports
exports.default = router;
//# sourceMappingURL=publicRoutes.js.map