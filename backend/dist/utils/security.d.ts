export declare const getJwtSecret: () => string;
export declare const hmacSha256Hex: (value: string, secret: string) => string;
export declare const hashIp: (ip: string | null | undefined) => string | null;
export declare const normalizeUserAgent: (ua: string | null | undefined) => string | null;
export declare const hashToken: (token: string) => string;
export declare const randomOpaqueToken: (bytes?: number) => string;
//# sourceMappingURL=security.d.ts.map