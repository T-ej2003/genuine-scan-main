export type CanonicalLabelBlock =
  | {
      type: "qr";
      xMm: number;
      yMm: number;
      widthMm: number;
      heightMm: number;
      rotation?: number;
      payload: { scanUrl: string };
    }
  | {
      type: "text";
      xMm: number;
      yMm: number;
      widthMm?: number;
      heightMm?: number;
      rotation?: number;
      payload: { text: string; font?: string; align?: "left" | "center" | "right" };
    };

export type CanonicalLabelDocument = {
  widthMm: number;
  heightMm: number;
  orientation: "PORTRAIT" | "LANDSCAPE";
  quietZoneMm: number;
  densityHintDpi?: number | null;
  copies: number;
  qrReference: {
    qrId: string;
    code: string;
    scanUrl: string;
  };
  batchContext: {
    batchId: string;
    batchName?: string | null;
    printJobId: string;
    printItemId?: string | null;
    reissueOfJobId?: string | null;
  };
  blocks: CanonicalLabelBlock[];
};

export const buildCanonicalQrLabel = (params: {
  qrId: string;
  code: string;
  scanUrl: string;
  batchId: string;
  batchName?: string | null;
  printJobId: string;
  printItemId?: string | null;
  reissueOfJobId?: string | null;
  labelWidthMm?: number;
  labelHeightMm?: number;
  dpi?: number | null;
}) => ({
  widthMm: Math.max(25, Number(params.labelWidthMm || 50)),
  heightMm: Math.max(20, Number(params.labelHeightMm || 50)),
  orientation: "PORTRAIT" as const,
  quietZoneMm: 2,
  densityHintDpi: params.dpi || 300,
  copies: 1,
  qrReference: {
    qrId: params.qrId,
    code: params.code,
    scanUrl: params.scanUrl,
  },
  batchContext: {
    batchId: params.batchId,
    batchName: params.batchName || null,
    printJobId: params.printJobId,
    printItemId: params.printItemId || null,
    reissueOfJobId: params.reissueOfJobId || null,
  },
  blocks: [
    {
      type: "qr" as const,
      xMm: 2,
      yMm: 2,
      widthMm: Math.max(20, Number(params.labelWidthMm || 50) - 4),
      heightMm: Math.max(20, Number(params.labelHeightMm || 50) - 4),
      payload: {
        scanUrl: params.scanUrl,
      },
    },
  ],
}) satisfies CanonicalLabelDocument;
