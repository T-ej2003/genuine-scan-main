import { Card, CardContent } from "@/components/ui/card";

type ManufacturerSummaryCardsProps = {
  total: number;
  active: number;
  inactive: number;
  assignedBatches: number;
  pendingPrintBatches: number;
};

const SUMMARY_ITEMS: Array<{ key: keyof ManufacturerSummaryCardsProps; label: string }> = [
  { key: "total", label: "Visible manufacturers" },
  { key: "active", label: "Active" },
  { key: "inactive", label: "Inactive" },
  { key: "assignedBatches", label: "Assigned batches" },
  { key: "pendingPrintBatches", label: "Needs print action" },
];

export function ManufacturerSummaryCards(props: ManufacturerSummaryCardsProps) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      {SUMMARY_ITEMS.map((item) => (
        <Card key={item.key}>
          <CardContent className="pt-6">
            <div className="text-sm text-muted-foreground">{item.label}</div>
            <div className="mt-2 text-2xl font-semibold">{props[item.key]}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
