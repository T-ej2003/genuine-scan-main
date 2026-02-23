"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluatePolicyRulesForIncidentVolume = exports.evaluatePolicyRulesForScan = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../../config/database"));
const auditService_1 = require("../auditService");
const incidentService_1 = require("../incidentService");
const notificationService_1 = require("../notificationService");
const ALERT_DEDUPE_WINDOW_MS = 15 * 60_000;
const clampInt = (value, fallback) => {
    const n = Number(value);
    if (!Number.isFinite(n))
        return fallback;
    return Math.floor(n);
};
const scoreFromRatio = (observed, threshold) => {
    const safeThreshold = Math.max(1, threshold);
    const ratio = observed / safeThreshold;
    if (!Number.isFinite(ratio) || ratio <= 0)
        return 0;
    // 1.0 => 60, 2.0 => 90, capped at 100
    const score = Math.round(Math.min(100, 30 + ratio * 30));
    return Math.max(0, score);
};
const incidentSeverityFromAlertSeverity = (severity) => {
    if (severity === client_1.AlertSeverity.CRITICAL)
        return client_1.IncidentSeverity.CRITICAL;
    if (severity === client_1.AlertSeverity.HIGH)
        return client_1.IncidentSeverity.HIGH;
    if (severity === client_1.AlertSeverity.MEDIUM)
        return client_1.IncidentSeverity.MEDIUM;
    return client_1.IncidentSeverity.LOW;
};
const incidentPriorityDefaultFromSeverity = (severity) => {
    if (severity === client_1.IncidentSeverity.CRITICAL)
        return client_1.IncidentPriority.P1;
    if (severity === client_1.IncidentSeverity.HIGH)
        return client_1.IncidentPriority.P2;
    if (severity === client_1.IncidentSeverity.MEDIUM)
        return client_1.IncidentPriority.P3;
    return client_1.IncidentPriority.P4;
};
const ruleIncidentType = (ruleType) => {
    if (ruleType === client_1.PolicyRuleType.TOO_MANY_REPORTS)
        return client_1.IncidentType.OTHER;
    return client_1.IncidentType.DUPLICATE_SCAN;
};
const buildRuleMessage = (rule, observed) => {
    const window = Math.max(1, rule.windowMinutes);
    if (rule.ruleType === client_1.PolicyRuleType.DISTINCT_DEVICES) {
        return `Distinct devices exceeded threshold: ${observed}/${rule.threshold} within ${window} minutes.`;
    }
    if (rule.ruleType === client_1.PolicyRuleType.MULTI_COUNTRY) {
        return `Multiple countries detected: ${observed}/${rule.threshold} within ${window} minutes.`;
    }
    if (rule.ruleType === client_1.PolicyRuleType.BURST_SCANS) {
        return `Burst scans exceeded threshold: ${observed}/${rule.threshold} within ${window} minutes.`;
    }
    if (rule.ruleType === client_1.PolicyRuleType.TOO_MANY_REPORTS) {
        return `High incident volume detected: ${observed}/${rule.threshold} reports within ${window} minutes.`;
    }
    return `Policy rule triggered: ${rule.ruleType} (${observed}/${rule.threshold}).`;
};
const createRuleAlertIfFresh = async (input) => {
    const windowMs = input.dedupeWindowMs ?? ALERT_DEDUPE_WINDOW_MS;
    const since = new Date(Date.now() - windowMs);
    const existing = await database_1.default.policyAlert.findFirst({
        where: {
            licenseeId: input.licenseeId,
            alertType: client_1.PolicyAlertType.POLICY_RULE,
            policyRuleId: input.policyRuleId,
            createdAt: { gte: since },
            acknowledgedAt: null,
            batchId: input.batchId || null,
            qrCodeId: input.qrCodeId || null,
            manufacturerId: input.manufacturerId || null,
        },
        select: { id: true },
    });
    if (existing)
        return null;
    const created = await database_1.default.policyAlert.create({
        data: {
            licenseeId: input.licenseeId,
            alertType: client_1.PolicyAlertType.POLICY_RULE,
            severity: input.severity,
            message: input.message,
            score: input.score,
            policyRuleId: input.policyRuleId,
            batchId: input.batchId || null,
            qrCodeId: input.qrCodeId || null,
            manufacturerId: input.manufacturerId || null,
            details: input.details ?? null,
        },
    });
    await Promise.all([
        (0, notificationService_1.createRoleNotifications)({
            audience: client_1.NotificationAudience.SUPER_ADMIN,
            type: "policy_alert_created",
            title: "Policy rule alert generated",
            body: created.message,
            incidentId: created.incidentId || null,
            data: {
                alertId: created.id,
                alertType: created.alertType,
                policyRuleId: created.policyRuleId,
                severity: created.severity,
                score: created.score,
                licenseeId: created.licenseeId,
                targetRoute: "/ir",
            },
            channels: [client_1.NotificationChannel.WEB],
        }),
        (0, notificationService_1.createRoleNotifications)({
            audience: client_1.NotificationAudience.LICENSEE_ADMIN,
            licenseeId: created.licenseeId,
            type: "policy_alert_created",
            title: "Policy rule alert generated",
            body: created.message,
            incidentId: created.incidentId || null,
            data: {
                alertId: created.id,
                alertType: created.alertType,
                policyRuleId: created.policyRuleId,
                severity: created.severity,
                score: created.score,
                licenseeId: created.licenseeId,
                targetRoute: "/ir",
            },
            channels: [client_1.NotificationChannel.WEB],
        }),
    ]);
    return created;
};
const resolveActiveRulesForLicensee = async (licenseeId) => {
    const licensee = await database_1.default.licensee.findUnique({
        where: { id: licenseeId },
        select: { orgId: true },
    });
    const orgId = licensee?.orgId || null;
    const whereOr = [{ licenseeId }];
    if (orgId)
        whereOr.push({ orgId });
    whereOr.push({ licenseeId: null, orgId: null });
    const rules = await database_1.default.policyRule.findMany({
        where: {
            isActive: true,
            OR: whereOr,
        },
        orderBy: [{ createdAt: "asc" }],
    });
    return { rules, orgId };
};
const evaluatePolicyRulesForScan = async (input) => {
    const now = new Date();
    const { rules } = await resolveActiveRulesForLicensee(input.licenseeId);
    const createdAlerts = [];
    const createdIncidentIds = [];
    for (const rule of rules) {
        if (rule.manufacturerId) {
            if (!input.manufacturerId || input.manufacturerId !== rule.manufacturerId)
                continue;
        }
        if (rule.ruleType === client_1.PolicyRuleType.TOO_MANY_REPORTS)
            continue; // evaluated on incident creation
        const windowMinutes = Math.max(1, clampInt(rule.windowMinutes, 60));
        const threshold = Math.max(1, clampInt(rule.threshold, 1));
        const since = new Date(now.getTime() - windowMinutes * 60_000);
        let observed = 0;
        let sample = null;
        if (rule.ruleType === client_1.PolicyRuleType.DISTINCT_DEVICES) {
            const groups = await database_1.default.qrScanLog.groupBy({
                by: ["device"],
                where: {
                    qrCodeId: input.qrCodeId,
                    scannedAt: { gte: since },
                    device: { not: null },
                },
                _count: { _all: true },
            });
            observed = groups.length;
            sample = groups
                .map((g) => ({ device: g.device, count: g._count?._all ?? 0 }))
                .filter((g) => Boolean(g.device))
                .slice(0, 6);
        }
        else if (rule.ruleType === client_1.PolicyRuleType.MULTI_COUNTRY) {
            const groups = await database_1.default.qrScanLog.groupBy({
                by: ["locationCountry"],
                where: {
                    qrCodeId: input.qrCodeId,
                    scannedAt: { gte: since },
                    locationCountry: { not: null },
                },
                _count: { _all: true },
            });
            observed = groups.length;
            sample = groups
                .map((g) => ({ country: g.locationCountry, count: g._count?._all ?? 0 }))
                .filter((g) => Boolean(g.country))
                .slice(0, 6);
        }
        else if (rule.ruleType === client_1.PolicyRuleType.BURST_SCANS) {
            observed = await database_1.default.qrScanLog.count({
                where: {
                    qrCodeId: input.qrCodeId,
                    scannedAt: { gte: since },
                },
            });
        }
        else {
            continue;
        }
        if (observed < threshold)
            continue;
        const message = buildRuleMessage(rule, observed);
        const score = scoreFromRatio(observed, threshold);
        const alert = await createRuleAlertIfFresh({
            licenseeId: input.licenseeId,
            policyRuleId: rule.id,
            message,
            severity: rule.severity,
            score,
            batchId: input.batchId || null,
            qrCodeId: input.qrCodeId,
            manufacturerId: input.manufacturerId || null,
            details: {
                rule: {
                    id: rule.id,
                    name: rule.name,
                    ruleType: rule.ruleType,
                    threshold,
                    windowMinutes,
                },
                observed,
                sample,
                code: input.code,
            },
        });
        if (!alert)
            continue;
        createdAlerts.push(alert);
        await (0, auditService_1.createAuditLog)({
            licenseeId: input.licenseeId,
            action: "POLICY_RULE_TRIGGERED",
            entityType: "PolicyRule",
            entityId: rule.id,
            details: {
                alertId: alert.id,
                code: input.code,
                qrCodeId: input.qrCodeId,
                batchId: input.batchId || null,
                manufacturerId: input.manufacturerId || null,
                observed,
                threshold,
                windowMinutes,
            },
        });
        if (!rule.autoCreateIncident)
            continue;
        const incidentSeverity = rule.incidentSeverity || incidentSeverityFromAlertSeverity(rule.severity);
        const incidentPriority = rule.incidentPriority || incidentPriorityDefaultFromSeverity(incidentSeverity);
        const incidentType = ruleIncidentType(rule.ruleType);
        const incident = await database_1.default.incident.create({
            data: {
                qrCodeId: input.qrCodeId,
                qrCodeValue: input.code,
                licenseeId: input.licenseeId,
                reportedBy: "ADMIN",
                incidentType,
                severity: incidentSeverity,
                severityOverridden: true,
                priority: incidentPriority,
                description: message,
                photos: [],
                tags: ["policy_rule", String(rule.ruleType).toLowerCase()],
                status: client_1.IncidentStatus.NEW,
                slaDueAt: (0, incidentService_1.computeSlaDueAt)(incidentSeverity),
            },
        });
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.SYSTEM,
            actorUserId: null,
            eventType: client_1.IncidentEventType.CREATED,
            eventPayload: {
                source: "policy_rule",
                policyRuleId: rule.id,
                policyAlertId: alert.id,
                ruleType: rule.ruleType,
                observed,
                threshold,
                windowMinutes,
            },
        });
        await database_1.default.policyAlert.update({
            where: { id: alert.id },
            data: { incidentId: incident.id },
        });
        createdIncidentIds.push(incident.id);
    }
    return { alerts: createdAlerts, incidents: createdIncidentIds };
};
exports.evaluatePolicyRulesForScan = evaluatePolicyRulesForScan;
const evaluatePolicyRulesForIncidentVolume = async (input) => {
    const licenseeId = String(input.licenseeId || "").trim();
    if (!licenseeId)
        return { alerts: [] };
    const now = new Date();
    const { rules } = await resolveActiveRulesForLicensee(licenseeId);
    const createdAlerts = [];
    for (const rule of rules) {
        if (rule.ruleType !== client_1.PolicyRuleType.TOO_MANY_REPORTS)
            continue;
        if (rule.manufacturerId && input.manufacturerId && rule.manufacturerId !== input.manufacturerId)
            continue;
        const windowMinutes = Math.max(1, clampInt(rule.windowMinutes, 60));
        const threshold = Math.max(1, clampInt(rule.threshold, 1));
        const since = new Date(now.getTime() - windowMinutes * 60_000);
        const where = {
            licenseeId,
            createdAt: { gte: since },
            status: { not: client_1.IncidentStatus.REJECTED_SPAM },
        };
        const observed = await database_1.default.incident.count({ where });
        if (observed < threshold)
            continue;
        const message = buildRuleMessage(rule, observed);
        const score = scoreFromRatio(observed, threshold);
        const alert = await createRuleAlertIfFresh({
            licenseeId,
            policyRuleId: rule.id,
            message,
            severity: rule.severity,
            score,
            details: {
                rule: {
                    id: rule.id,
                    name: rule.name,
                    ruleType: rule.ruleType,
                    threshold,
                    windowMinutes,
                },
                observed,
                incidentId: input.incidentId,
            },
        });
        if (!alert)
            continue;
        createdAlerts.push(alert);
        await database_1.default.policyAlert.update({
            where: { id: alert.id },
            data: { incidentId: input.incidentId },
        });
        await (0, auditService_1.createAuditLog)({
            licenseeId,
            action: "POLICY_RULE_TRIGGERED",
            entityType: "PolicyRule",
            entityId: rule.id,
            details: {
                alertId: alert.id,
                incidentId: input.incidentId,
                observed,
                threshold,
                windowMinutes,
            },
        });
    }
    return { alerts: createdAlerts };
};
exports.evaluatePolicyRulesForIncidentVolume = evaluatePolicyRulesForIncidentVolume;
//# sourceMappingURL=policyRuleEngineService.js.map