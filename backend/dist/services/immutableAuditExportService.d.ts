export declare const buildImmutableBatchAuditPackage: (batchId: string) => Promise<{
    fileName: string;
    buffer: Buffer<ArrayBufferLike>;
    metadata: {
        batchId: string;
        generatedAt: string;
        qrCount: number;
        eventCount: number;
        alertCount: number;
        chainRoot: string;
        integrityHash: string;
        signatureAlgorithm: "ed25519" | "hmac-sha256";
    };
}>;
//# sourceMappingURL=immutableAuditExportService.d.ts.map