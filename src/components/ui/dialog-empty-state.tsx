import { Button } from "@/components/ui/button";

type DialogEmptyStateProps = {
  title: string;
  description: string;
  onClose: () => void;
  closeLabel?: string;
};

export function DialogEmptyState({
  title,
  description,
  onClose,
  closeLabel = "Close dialog",
}: DialogEmptyStateProps) {
  return (
    <div className="mt-2 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
      <div className="font-medium">{title}</div>
      <p className="mt-2 leading-6 text-amber-900">{description}</p>
      <div className="mt-4 flex justify-end">
        <Button variant="outline" onClick={onClose}>
          {closeLabel}
        </Button>
      </div>
    </div>
  );
}
