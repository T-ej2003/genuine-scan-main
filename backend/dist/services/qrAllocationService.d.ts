import { Prisma } from "@prisma/client";
type DbClient = Prisma.TransactionClient;
export declare const lockLicenseeAllocation: (tx: DbClient, licenseeId: string) => Promise<void>;
export declare const getNextLicenseeQrNumber: (tx: DbClient, licenseeId: string) => Promise<number>;
export type AllocateQrRangeParams = {
    licenseeId: string;
    startNumber: number;
    endNumber: number;
    createdByUserId?: string | null;
    source?: string | null;
    requestId?: string | null;
    createReceivedBatch?: boolean;
    receivedBatchName?: string | null;
    tx?: DbClient;
};
export declare const allocateQrRange: (params: AllocateQrRangeParams) => Promise<{
    range: {
        licenseeId: string;
        createdAt: Date;
        updatedAt: Date;
        id: string;
        startCode: string;
        endCode: string;
        totalCodes: number;
        usedCodes: number;
    };
    createdCount: number;
    startCode: string;
    endCode: string;
    totalCodes: number;
    receivedBatch: {
        id: string;
        name: string;
    } | null;
}>;
export {};
//# sourceMappingURL=qrAllocationService.d.ts.map