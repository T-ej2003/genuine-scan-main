export type DashboardGraphView = "scans" | "confidence" | "printed" | "batches";

type QrStatusBreakdown = {
  dormant: number;
  allocated: number;
  printed: number;
  scanned: number;
};

export const DASHBOARD_GRAPH_OPTIONS: Array<{ id: DashboardGraphView; label: string; description: string }> = [
  { id: "scans", label: "Scans over time", description: "Shows customer scan activity when the data is available." },
  { id: "confidence", label: "Genuine vs suspicious", description: "Compares verified scans with scans that need review." },
  { id: "printed", label: "Labels printed", description: "Tracks labels that have been confirmed as printed." },
  { id: "batches", label: "Top scanned batches", description: "Highlights the batches customers scan most often." },
];

export const buildOverviewLifecycleSteps = (qrStatusData: QrStatusBreakdown) => [
  {
    label: "Issue",
    title: "QR labels ready",
    body: `${qrStatusData.dormant.toLocaleString()} waiting for allocation.`,
    state: qrStatusData.dormant > 0 ? ("current" as const) : ("complete" as const),
  },
  {
    label: "Assign",
    title: "Batch assignment",
    body: `${qrStatusData.allocated.toLocaleString()} assigned to production.`,
    state: qrStatusData.allocated > 0 ? ("complete" as const) : ("pending" as const),
  },
  {
    label: "Print",
    title: "Print labels",
    body: `${qrStatusData.printed.toLocaleString()} labels confirmed as printed.`,
    state: qrStatusData.printed > 0 ? ("complete" as const) : ("pending" as const),
  },
  {
    label: "Verify",
    title: "Public checks",
    body: `${qrStatusData.scanned.toLocaleString()} customer verification events.`,
    state: qrStatusData.scanned > 0 ? ("complete" as const) : ("pending" as const),
  },
  {
    label: "Review",
    title: "Review issues",
    body: "Scan results and workspace history remain reviewable.",
    state: "current" as const,
  },
];
