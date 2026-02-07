export type QrTokenPayload = {
    qr_id: string;
    batch_id: string | null;
    licensee_id: string;
    manufacturer_id?: string | null;
    iat: number;
    exp?: number;
    nonce: string;
};
export declare const randomNonce: () => string;
export declare const hashToken: (token: string) => string;
export declare const signQrPayload: (payload: QrTokenPayload) => string;
export declare const verifyQrToken: (token: string) => {
    payload: QrTokenPayload;
};
export declare const buildScanUrl: (token: string) => string;
//# sourceMappingURL=qrTokenService.d.ts.map