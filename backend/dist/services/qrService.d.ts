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
export declare const markProductBatchAsPrinted: (productBatchId: string, manufacturerId: string) => Promise<number>;
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
            manufacturerId: string | null;
            printedAt: Date | null;
            printPackDownloadedAt: Date | null;
            printPackDownloadedByUserId: string | null;
        }) | null;
        productBatch: ({
            manufacturer: {
                id: string;
                email: string;
                name: string;
                location: string | null;
                website: string | null;
            } | null;
            parentBatch: {
                id: string;
                name: string;
            };
        } & {
            id: string;
            licenseeId: string;
            createdAt: Date;
            updatedAt: Date;
            description: string | null;
            startCode: string;
            endCode: string;
            totalCodes: number;
            manufacturerId: string | null;
            printedAt: Date | null;
            printPackDownloadedAt: Date | null;
            printPackDownloadedByUserId: string | null;
            parentBatchId: string;
            productName: string;
            productCode: string;
            serialStart: number;
            serialEnd: number;
            serialFormat: string;
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
        batchId: string | null;
        productBatchId: string | null;
    };
    isFirstScan: boolean;
}>;
export declare const getQRStats: (licenseeId?: string) => Promise<{
    total: number;
    byStatus: Record<string, number>;
}>;
//# sourceMappingURL=qrService.d.ts.map