import { Response } from "express";
type CsvValue = string | number | boolean | null | undefined;
export type QrZipTier = "standard" | "high" | "ultra";
export type QrZipProfile = {
    tier: QrZipTier;
    zipCompressionLevel: number;
    pngWidth: number;
    pngConcurrency: number;
    dbChunkSize: number;
};
export type QrZipEntry = {
    code: string;
    url: string;
    manifestValues: CsvValue[];
};
type StreamQrZipOptions = {
    res: Response;
    fileName: string;
    totalCount: number;
    manifestHeader: string[];
    entries: AsyncIterable<QrZipEntry>;
    profile?: QrZipProfile;
};
export declare const resolveQrZipProfile: (totalCount: number) => QrZipProfile;
export declare const streamQrZipToResponse: ({ res, fileName, totalCount, manifestHeader, entries, profile: explicitProfile, }: StreamQrZipOptions) => Promise<QrZipProfile>;
export {};
//# sourceMappingURL=qrZipStreamService.d.ts.map