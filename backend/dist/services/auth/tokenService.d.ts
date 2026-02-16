import type { JWTPayload } from "../../types";
export declare const ACCESS_TOKEN_COOKIE = "aq_access";
export declare const REFRESH_TOKEN_COOKIE = "aq_refresh";
export declare const CSRF_TOKEN_COOKIE = "aq_csrf";
export declare const getAccessTokenTtlMinutes: () => number;
export declare const getRefreshTokenTtlDays: () => number;
export declare const signAccessToken: (payload: JWTPayload) => string;
export declare const verifyAccessToken: (token: string) => JWTPayload;
export declare const newRefreshToken: () => string;
export declare const hashRefreshToken: (token: string) => string;
export declare const newCsrfToken: () => string;
//# sourceMappingURL=tokenService.d.ts.map