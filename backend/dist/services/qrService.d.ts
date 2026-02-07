export declare const generateQRCode: (prefix: string, number: number) => string;
export declare const parseQRCode: (code: string) => {
    prefix: string;
    number: number;
} | null;
export declare const makeProductCode: (input: string) => string;
export declare const buildVerifyUrl: (code: string) => string;
export declare const generateQRCodesForRange: (licenseeId: string, prefix: string, startNumber: number, endNumber: number) => Promise<number>;
export declare const activateQRCodes: (licenseeId: string, codes: string[]) => Promise<number>;
export declare const allocateQRCodesToBatch: (batchId: string, licenseeId: string, startCode: string, endCode: string) => Promise<number>;
export declare const markBatchAsPrinted: (batchId: string, manufacturerId: string) => Promise<number>;
export declare const recordScan: (code: string, meta?: {
    ipAddress?: string | null;
    userAgent?: string | null;
    device?: string | null;
    latitude?: number | null;
    longitude?: number | null;
    accuracy?: number | null;
}) => Promise<{
    qrCode: {
        licensee: {
            id: string;
            name: string;
            location: string | null;
            website: string | null;
            isActive: boolean;
            createdAt: Date;
            updatedAt: Date;
            prefix: string;
            description: string | null;
            brandName: string | null;
            supportEmail: string | null;
            supportPhone: string | null;
        };
        batch: ({
            manufacturer: {
                id: string;
                email: string;
                name: string;
                location: string | null;
                website: string | null;
            } | null;
        } & {
            id: string;
            name: string;
            licenseeId: string;
            createdAt: Date;
            updatedAt: Date;
            startCode: string;
            endCode: string;
            totalCodes: number;
            printedAt: Date | null;
            manufacturerId: string | null;
            printPackDownloadedAt: Date | null;
            printPackDownloadedByUserId: string | null;
        }) | null;
    } & {
        id: string;
        licenseeId: string;
        createdAt: Date;
        updatedAt: Date;
        code: string;
        status: import(".prisma/client").$Enums.QRStatus;
        scannedAt: Date | null;
        scanCount: number;
        printedAt: Date | null;
        redeemedAt: Date | null;
        redeemedDeviceFingerprint: string | null;
        lastScanIp: string | null;
        lastScanUserAgent: string | null;
        lastScanDevice: string | null;
        blockedAt: Date | null;
        tokenNonce: string | null;
        tokenIssuedAt: Date | null;
        tokenExpiresAt: Date | null;
        tokenHash: string | null;
        batchId: string | null;
        printedByUserId: string | null;
        printJobId: string | null;
    };
    isFirstScan: boolean;
}>;
export declare const getQRStats: (licenseeId?: string) => Promise<{
    total: number;
    byStatus: Record<string, number>;
}>;
//# sourceMappingURL=qrService.d.ts.map