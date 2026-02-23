"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const rbac_1 = require("../middleware/rbac");
const tenantIsolation_1 = require("../middleware/tenantIsolation");
const auditController_1 = require("../controllers/auditController");
const csrf_1 = require("../middleware/csrf");
const router = (0, express_1.Router)();
router.get("/logs", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.getLogs);
router.get("/logs/export", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.exportLogsCsv);
router.get("/stream", auth_1.authenticateSSE, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.streamLogs);
router.get("/fraud-reports", auth_1.authenticate, rbac_1.requirePlatformAdmin, tenantIsolation_1.enforceTenantIsolation, auditController_1.getFraudReports);
router.post("/fraud-reports/:id/respond", auth_1.authenticate, rbac_1.requirePlatformAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, auditController_1.respondToFraudReport);
exports.default = router;
//# sourceMappingURL=auditRoutes.js.map