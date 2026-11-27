import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import apiClient from "@/lib/api-client";
import type { PrintRetirementRow } from "@/features/batches/types";

type Action = "REQUEST" | "APPROVE" | "REJECT";

export function PrintRetirementPanel({ jobId, onChanged }: { jobId: string; onChanged?: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<PrintRetirementRow[]>([]);
  const [cursor, setCursor] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  useEffect(() => {
    if (!open) return;
    let current = true;
    setLoading(true);
    setError(null);
    void apiClient.getPrintRetirements(jobId, cursor).then((result) => {
      if (!current) return;
      setRows(result.success && result.data ? result.data : []);
      if (!result.success) setError(result.error || "Retirement information could not be loaded.");
    }).catch(() => {
      if (current) {
        setRows([]);
        setError("Retirement information could not be loaded.");
      }
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [open, jobId, cursor, revision]);

  async function submit(itemId: string, action: Action) {
    setBusy(true);
    setActionError(null);
    try {
      const result = await apiClient.decidePrintRetirement(jobId, { itemId, action, reason: reason.trim() });
      if (!result.success) {
        setActionError(result.error || "The decision could not be saved.");
        if (result.status !== 409) return;
      } else {
        setReason("");
        onChanged?.();
      }
      setCursor(undefined);
      setRevision((value) => value + 1);
    } catch {
      setActionError("The decision could not be verified. Refresh before submitting again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="rounded-md border p-3 text-sm" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="cursor-pointer font-medium">Retire affected labels</summary>
      {open && (loading ? <div className="p-2" role="status">Checking retirement options…</div> : error ? (
        <div className="mt-2" role="alert">{error}</div>
      ) : (
        <div className="mt-2 space-y-2">
          <p>Retirement permanently invalidates the label. Whether it physically printed remains unknown.</p>
          {rows.length === 0 ? <p>No labels or requests on this page.</p> : null}
          {rows.some((item) => item.canRequest || item.canApprove || item.canReject) ? (
            <label className="block">Reason
              <Textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} />
            </label>
          ) : null}
          {actionError ? <p role="alert">{actionError}</p> : null}
          {rows.map((item) => (
            <div key={item.itemId} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2">
              <span>{item.serial || "Serial unavailable"} · {item.status === "PENDING" ? "Awaiting licensee decision"
                : item.status === "EXECUTED" ? "Retired" : item.status === "REJECTED" ? "Rejected" : "Eligible to request"}</span>
              {item.requestReason ? <p className="basis-full text-muted-foreground">{item.requestReason}</p> : null}
              {item.canRequest ? <Button size="sm" disabled={busy || reason.trim().length < 8}
                onClick={() => void submit(item.itemId, "REQUEST")}>Request retirement</Button> : null}
              {item.canApprove || item.canReject ? (
                <div className="flex gap-2">
                  {item.canReject ? <Button size="sm" variant="outline" disabled={busy || reason.trim().length < 8}
                    onClick={() => void submit(item.itemId, "REJECT")}>Reject</Button> : null}
                  {item.canApprove ? <Button size="sm" variant="destructive" disabled={busy || reason.trim().length < 8}
                    onClick={() => void submit(item.itemId, "APPROVE")}>Approve retirement</Button> : null}
                </div>
              ) : null}
            </div>
          ))}
          {rows.length === 50 ? <Button variant="outline" onClick={() => setCursor(rows[49].itemId)}>Next labels</Button> : null}
          {cursor ? <Button variant="outline" onClick={() => setCursor(undefined)}>First labels</Button> : null}
        </div>
      ))}
    </details>
  );
}
