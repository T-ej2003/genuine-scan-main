export declare const enforceIncidentRateLimit: (input: {
    ip?: string | null;
    qrCode?: string | null;
    deviceFp?: string | null;
}) => {
    blocked: boolean;
    retryAfterSec: number;
};
//# sourceMappingURL=incidentRateLimitService.d.ts.map