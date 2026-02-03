import { Prisma } from "@prisma/client";
type DbClient = Prisma.TransactionClient;
export type AllocateQrRangeParams = {
    licenseeId: string;
    startNumber: number;
    endNumber: number;
    createdByUserId?: string | null;
    source?: string | null;
    requestId?: string | null;
    createReceivedBatch?: boolean;
    tx?: DbClient;
};
export declare const allocateQrRange: (params: AllocateQrRangeParams) => Promise<{
    range: {
        id: string;
        licenseeId: string;
        createdAt: Date;
        updatedAt: Date;
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