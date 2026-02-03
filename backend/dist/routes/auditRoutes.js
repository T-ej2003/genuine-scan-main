"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const rbac_1 = require("../middleware/rbac");
const tenantIsolation_1 = require("../middleware/tenantIsolation");
const auditController_1 = require("../controllers/auditController");
const router = (0, express_1.Router)();
router.get("/logs", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.getLogs);
router.get("/logs/export", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.exportLogsCsv);
router.get("/stream", auth_1.authenticateSSE, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.streamLogs);
exports.default = router;
//# sourceMappingURL=auditRoutes.js.map