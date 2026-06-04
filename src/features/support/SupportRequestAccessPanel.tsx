import { ActionButton } from "@/components/ui/action-button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PageEmptyState, PageSection } from "@/components/page-patterns/PagePatterns";
import type { RequestAccessRecord } from "@/features/support/types";
import { REQUEST_ACCESS_STATUSES, toLabel } from "@/features/support/types";
import { createUiActionState } from "@/lib/ui-actions";

type SupportRequestAccessPanelProps = {
  records: RequestAccessRecord[];
  isLoading: boolean;
  canEdit: boolean;
  notes: Record<string, string>;
  isUpdating: boolean;
  onNoteChange: (recordId: string, value: string) => void;
  onUpdate: (record: RequestAccessRecord, status: RequestAccessRecord["status"]) => void;
};

export function SupportRequestAccessPanel({
  records,
  isLoading,
  canEdit,
  notes,
  isUpdating,
  onNoteChange,
  onUpdate,
}: SupportRequestAccessPanelProps) {
  return (
    <PageSection
      title="Access requests"
      description="Review onboarding requests from brands and manufacturers before inviting platform users."
      action={<Badge variant="outline">{records.length}</Badge>}
    >
      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading access requests...</div>
      ) : records.length === 0 ? (
        <PageEmptyState
          title="No access requests"
          description="Public access requests will appear here after the request-access form is submitted."
        />
      ) : (
        <div className="grid gap-3 xl:grid-cols-2">
          {records.slice(0, 8).map((record) => (
            <RequestAccessCard
              key={record.id}
              record={record}
              canEdit={canEdit}
              note={notes[record.id] ?? record.internalNote ?? ""}
              isUpdating={isUpdating}
              onNoteChange={(value) => onNoteChange(record.id, value)}
              onUpdate={(status) => onUpdate(record, status)}
            />
          ))}
        </div>
      )}
    </PageSection>
  );
}

function RequestAccessCard({
  record,
  canEdit,
  note,
  isUpdating,
  onNoteChange,
  onUpdate,
}: {
  record: RequestAccessRecord;
  canEdit: boolean;
  note: string;
  isUpdating: boolean;
  onNoteChange: (value: string) => void;
  onUpdate: (status: RequestAccessRecord["status"]) => void;
}) {
  return (
    <div className="rounded-2xl border p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold">{record.companyName}</p>
          <p className="text-xs text-muted-foreground">
            {record.fullName} · {record.workEmail}
          </p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">{record.referenceCode}</p>
        </div>
        <Badge variant="outline">{toLabel(record.status)}</Badge>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <span>Role: {record.roleTitle}</span>
        <span>Country: {record.country}</span>
        <span>Volume: {record.monthlyGarmentVolume}</span>
        <span>Email: {toLabel(record.adminEmailDeliveryStatus || "UNKNOWN")}</span>
      </div>
      <p className="mt-3 line-clamp-3 text-xs text-slate-700">{record.message}</p>
      {canEdit ? (
        <div className="mt-3 space-y-2 rounded-lg border bg-muted/30 p-3">
          <Label htmlFor={`request-access-note-${record.id}`} className="text-xs font-semibold">
            Internal note
          </Label>
          <Textarea
            id={`request-access-note-${record.id}`}
            rows={2}
            value={note}
            onChange={(event) => onNoteChange(event.target.value)}
            placeholder="Next step, owner, or qualification note."
          />
          <div className="flex flex-wrap gap-2">
            {REQUEST_ACCESS_STATUSES.filter((status) => status !== record.status)
              .slice(0, 3)
              .map((status) => (
                <ActionButton
                  key={status}
                  size="sm"
                  variant="outline"
                  onClick={() => onUpdate(status)}
                  state={
                    isUpdating
                      ? createUiActionState("pending", "Saving access request update.")
                      : createUiActionState("enabled")
                  }
                  idleLabel={toLabel(status)}
                  pendingLabel="Saving..."
                  showReasonBelow={false}
                />
              ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
