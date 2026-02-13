type CaptchaResult = {
    ok: boolean;
    reason?: string;
};
export declare const verifyCaptchaToken: (token?: string | null, remoteIp?: string | null) => Promise<CaptchaResult>;
export {};
//# sourceMappingURL=captchaService.d.ts.map