import { Button } from "@/components/ui/button";

export function PrinterZplSetupNotice({ printer, onOpenDiagnostics }: {
  printer: { languages?: string[]; dpi?: number | null };
  onOpenDiagnostics: () => void;
}) {
  const zpl = printer.languages?.some((language) => ["ZPL", "ZPL2", "ZPL-II", "ZSIM"].includes(language.toUpperCase()));
  if (zpl && printer.dpi === 300) return null;
  return <div className="rounded-lg border p-3 text-sm">
    {printer.dpi != null && printer.dpi !== 300
      ? `This printer reports ${printer.dpi} dpi; MSCQR's ZPL label needs 300 dpi. Choose a matching printer or driver.`
      : "ZPL mode or 300 dpi is not confirmed for this printer. Check its language mode and 40 × 50 mm media before printing."}
    <Button className="ml-2" size="sm" variant="outline" onClick={onOpenDiagnostics}>Confirm ZPL setup</Button>
  </div>;
}
