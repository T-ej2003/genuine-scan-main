import { QRStatus } from "@prisma/client";

export type ScanOutcome =
  | "VALID"
  | "ALREADY_REDEEMED"
  | "NOT_PRINTED"
  | "SUSPICIOUS"
  | "BLOCKED";

export type ScanDecision = {
  outcome: ScanOutcome;
  isFirstScan: boolean;
  allowRedeem: boolean;
};

export const evaluateScanPolicy = (status: QRStatus): ScanDecision => {
  switch (status) {
    case QRStatus.PRINTED:
      return { outcome: "VALID", isFirstScan: true, allowRedeem: true };
    case QRStatus.REDEEMED:
    case QRStatus.SCANNED:
      return { outcome: "ALREADY_REDEEMED", isFirstScan: false, allowRedeem: false };
    case QRStatus.ACTIVATED:
      return { outcome: "SUSPICIOUS", isFirstScan: false, allowRedeem: false };
    case QRStatus.BLOCKED:
      return { outcome: "BLOCKED", isFirstScan: false, allowRedeem: false };
    case QRStatus.DORMANT:
    case QRStatus.ACTIVE:
    case QRStatus.ALLOCATED:
    default:
      return { outcome: "NOT_PRINTED", isFirstScan: false, allowRedeem: false };
  }
};
