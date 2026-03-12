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
    customerUserId?: string | null;
    ownershipId?: string | null;
    ownershipMatchMethod?: string | null;
    isTrustedOwnerContext?: boolean;
}) => Promise<{
    qrCode: {
        licensee: {
            createdAt: Date;
            updatedAt: Date;
            id: string;
            orgId: string;
            name: string;
            prefix: string;
            description: string | null;
            brandName: string | null;
            location: string | null;
            website: string | null;
            supportEmail: string | null;
            supportPhone: string | null;
            isActive: boolean;
            suspendedAt: Date | null;
            suspendedReason: string | null;
        };
        batch: ({
            manufacturer: {
                id: string;
                name: string;
                location: string | null;
                website: string | null;
                email: string;
            } | null;
        } & {
            manufacturerId: string | null;
            licenseeId: string;
            createdAt: Date;
            updatedAt: Date;
            id: string;
            name: string;
            suspendedAt: Date | null;
            suspendedReason: string | null;
            parentBatchId: string | null;
            rootBatchId: string | null;
            startCode: string;
            endCode: string;
            totalCodes: number;
            printedAt: Date | null;
            printPackDownloadedAt: Date | null;
            printPackDownloadedByUserId: string | null;
        }) | null;
    } & {
        licenseeId: string;
        createdAt: Date;
        updatedAt: Date;
        id: string;
        status: import(".prisma/client").$Enums.QRStatus;
        code: string;
        batchId: string | null;
        printedAt: Date | null;
        scannedAt: Date | null;
        scanCount: number;
        printedByUserId: string | null;
        redeemedAt: Date | null;
        redeemedDeviceFingerprint: string | null;
        lastScanIp: string | null;
        lastScanUserAgent: string | null;
        lastScanDevice: string | null;
        blockedAt: Date | null;
        underInvestigationAt: Date | null;
        underInvestigationReason: string | null;
        tokenNonce: string | null;
        tokenIssuedAt: Date | null;
        tokenExpiresAt: Date | null;
        tokenHash: string | null;
        printJobId: string | null;
    };
    isFirstScan: boolean;
}>;
export declare const getQRStats: (licenseeId?: string) => Promise<{
    total: number;
    byStatus: Record<string, number>;
}>;
//# sourceMappingURL=qrService.d.ts.map