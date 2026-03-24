import React from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { INCIDENT_TYPE_OPTIONS, type LicenseeLite, type NewIncidentState, type PolicyFormState } from "@/features/ir/types";

type IncidentResponseAdminDialogsProps = {
  newIncidentOpen: boolean;
  onNewIncidentOpenChange: (open: boolean) => void;
  newIncident: NewIncidentState;
  onNewIncidentChange: React.Dispatch<React.SetStateAction<NewIncidentState>>;
  creatingIncident: boolean;
  onCreateIncident: () => Promise<void> | void;
  licensees: LicenseeLite[];
  policyDialogOpen: boolean;
  onPolicyDialogOpenChange: (open: boolean) => void;
  editingPolicy: any | null;
  policyForm: PolicyFormState;
  onPolicyFormChange: React.Dispatch<React.SetStateAction<PolicyFormState>>;
  policySaving: boolean;
  onSavePolicy: () => Promise<void> | void;
};

export function IncidentResponseAdminDialogs({
  newIncidentOpen,
  onNewIncidentOpenChange,
  newIncident,
  onNewIncidentChange,
  creatingIncident,
  onCreateIncident,
  licensees,
  policyDialogOpen,
  onPolicyDialogOpenChange,
  editingPolicy,
  policyForm,
  onPolicyFormChange,
  policySaving,
  onSavePolicy,
}: IncidentResponseAdminDialogsProps) {
  return (
    <>
      <Dialog open={newIncidentOpen} onOpenChange={onNewIncidentOpenChange}>
        <DialogContent className="sm:max-w-[720px]">
          <DialogHeader>
            <DialogTitle>Create incident</DialogTitle>
            <DialogDescription>Use this for manual cases or escalations from policy alerts.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Code value</Label>
                <Input
                  value={newIncident.qrCodeValue}
                  onChange={(event) => onNewIncidentChange((previous) => ({ ...previous, qrCodeValue: event.target.value }))}
                  placeholder="A0000000001"
                />
              </div>

              <div className="space-y-2">
                <Label>Licensee (optional)</Label>
                <Select
                  value={newIncident.licenseeId}
                  onValueChange={(value) => onNewIncidentChange((previous) => ({ ...previous, licenseeId: value }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Auto-detect from code" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">Auto-detect from code</SelectItem>
                    {licensees.map((licensee) => (
                      <SelectItem key={licensee.id} value={licensee.id}>
                        {licensee.name} ({licensee.prefix})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label>Type</Label>
                <Select value={newIncident.incidentType} onValueChange={(value) => onNewIncidentChange((previous) => ({ ...previous, incidentType: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    {INCIDENT_TYPE_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Severity</Label>
                <Select value={newIncident.severity} onValueChange={(value) => onNewIncidentChange((previous) => ({ ...previous, severity: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">LOW</SelectItem>
                    <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                    <SelectItem value="HIGH">HIGH</SelectItem>
                    <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Priority</Label>
                <Select value={newIncident.priority} onValueChange={(value) => onNewIncidentChange((previous) => ({ ...previous, priority: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Priority" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="P1">P1</SelectItem>
                    <SelectItem value="P2">P2</SelectItem>
                    <SelectItem value="P3">P3</SelectItem>
                    <SelectItem value="P4">P4</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea
                value={newIncident.description}
                onChange={(event) => onNewIncidentChange((previous) => ({ ...previous, description: event.target.value }))}
                rows={4}
                placeholder="What happened and why this needs investigation."
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => onNewIncidentOpenChange(false)} disabled={creatingIncident}>
                Cancel
              </Button>
              <Button type="button" onClick={onCreateIncident} disabled={creatingIncident}>
                {creatingIncident ? "Creating..." : "Create incident"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={policyDialogOpen} onOpenChange={onPolicyDialogOpenChange}>
        <DialogContent className="sm:max-w-[760px]">
          <DialogHeader>
            <DialogTitle>{editingPolicy ? "Edit policy rule" : "Create policy rule"}</DialogTitle>
            <DialogDescription>
              Configure when the platform should raise alerts and optionally auto-create incidents.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  value={policyForm.name}
                  onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, name: event.target.value }))}
                  placeholder="e.g., Multi-country scans"
                />
              </div>
              <div className="space-y-2">
                <Label>Scope</Label>
                <Select
                  value={policyForm.licenseeId}
                  onValueChange={(value) => onPolicyFormChange((previous) => ({ ...previous, licenseeId: value }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select scope" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All licensees</SelectItem>
                    {licensees.map((licensee) => (
                      <SelectItem key={licensee.id} value={licensee.id}>
                        {licensee.name} ({licensee.prefix})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Description (optional)</Label>
              <Input
                value={policyForm.description}
                onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, description: event.target.value }))}
                placeholder="What this rule detects."
              />
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label>Rule type</Label>
                <Select value={policyForm.ruleType} onValueChange={(value) => onPolicyFormChange((previous) => ({ ...previous, ruleType: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select rule type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="DISTINCT_DEVICES">Distinct devices</SelectItem>
                    <SelectItem value="MULTI_COUNTRY">Multi-country</SelectItem>
                    <SelectItem value="BURST_SCANS">Burst scans</SelectItem>
                    <SelectItem value="TOO_MANY_REPORTS">Too many reports</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Threshold</Label>
                <Input value={policyForm.threshold} onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, threshold: event.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label>Window (minutes)</Label>
                <Input
                  value={policyForm.windowMinutes}
                  onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, windowMinutes: event.target.value }))}
                />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Alert severity</Label>
                <Select value={policyForm.severity} onValueChange={(value) => onPolicyFormChange((previous) => ({ ...previous, severity: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">LOW</SelectItem>
                    <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                    <SelectItem value="HIGH">HIGH</SelectItem>
                    <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-2 pt-7 text-sm">
                <input
                  type="checkbox"
                  checked={policyForm.isActive}
                  onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, isActive: event.target.checked }))}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <span>Active</span>
              </div>
            </div>

            <div className="space-y-3 rounded-lg border bg-slate-50 p-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={policyForm.autoCreateIncident}
                  onChange={(event) => onPolicyFormChange((previous) => ({ ...previous, autoCreateIncident: event.target.checked }))}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <span>Auto-create incident when this rule triggers</span>
              </label>

              {policyForm.autoCreateIncident ? (
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Incident severity</Label>
                    <Select
                      value={policyForm.incidentSeverity}
                      onValueChange={(value) => onPolicyFormChange((previous) => ({ ...previous, incidentSeverity: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="LOW">LOW</SelectItem>
                        <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                        <SelectItem value="HIGH">HIGH</SelectItem>
                        <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Incident priority</Label>
                    <Select
                      value={policyForm.incidentPriority}
                      onValueChange={(value) => onPolicyFormChange((previous) => ({ ...previous, incidentPriority: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Priority" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="P1">P1</SelectItem>
                        <SelectItem value="P2">P2</SelectItem>
                        <SelectItem value="P3">P3</SelectItem>
                        <SelectItem value="P4">P4</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => onPolicyDialogOpenChange(false)} disabled={policySaving}>
                Cancel
              </Button>
              <Button type="button" onClick={onSavePolicy} disabled={policySaving}>
                {policySaving ? "Saving..." : "Save"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
