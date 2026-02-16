import { QRStatus, type Prisma } from "@prisma/client";
import { classifyScan } from "./scanRiskService";
type RecordClassifiedScanInput = {
    qrId: string;
    currentStatus: QRStatus;
    allowRedeem: boolean;
    existingScannedAt?: Date | null;
    existingRedeemedAt?: Date | null;
    ipAddress?: string | null;
    ipHash?: string | null;
    userAgent?: string | null;
    device?: string | null;
    latitude?: number | null;
    longitude?: number | null;
    accuracy?: number | null;
    customerUserId?: string | null;
    anonVisitorId?: string | null;
    visitorFingerprint?: string | null;
    scannedAt?: Date;
};
export type RecordClassifiedScanResult = {
    qrCode: Prisma.QRCodeGetPayload<{
        include: {
            licensee: {
                select: {
                    id: true;
                    name: true;
                    prefix: true;
                    brandName: true;
                    location: true;
                    website: true;
                    supportEmail: true;
                    supportPhone: true;
                };
            };
            batch: {
                select: {
                    id: true;
                    name: true;
                    printedAt: true;
                    manufacturer: {
                        select: {
                            id: true;
                            name: true;
                            email: true;
                            location: true;
                            website: true;
                        };
                    };
                };
            };
        };
    }>;
    classification: ReturnType<typeof classifyScan>;
    ownership: {
        customerUserId: string;
        claimedAt: Date;
    } | null;
    location: {
        name: string | null;
        country: string | null;
        region: string | null;
        city: string | null;
    } | null;
};
export declare const recordClassifiedScan: (input: RecordClassifiedScanInput) => Promise<RecordClassifiedScanResult>;
export {};
//# sourceMappingURL=recordClassifiedScanService.d.ts.map