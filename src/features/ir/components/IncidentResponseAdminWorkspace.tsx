import React from "react";
import { Plus, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  type AlertFiltersState,
  type IncidentFiltersState,
  type LicenseeLite,
  type NewIncidentState,
  type PolicyFormState,
} from "@/features/ir/types";
import { IncidentResponseAdminDialogs } from "@/features/ir/components/IncidentResponseAdminDialogs";
import { IncidentResponseAdminTabs } from "@/features/ir/components/IncidentResponseAdminTabs";

type IncidentResponseAdminWorkspaceProps = {
  activeTab: "incidents" | "alerts" | "policies";
  onActiveTabChange: (value: "incidents" | "alerts" | "policies") => void;
  onRefreshActiveTab: () => Promise<void> | void;
  onOpenCreateIncident: () => void;
  onOpenCreatePolicy: () => void;
  incidentFilters: IncidentFiltersState;
  onIncidentFiltersChange: React.Dispatch<React.SetStateAction<IncidentFiltersState>>;
  onLoadIncidents: () => Promise<void> | void;
  licenseeOptions: Array<LicenseeLite | { id: string; name: string; prefix: string }>;
  incidentsLoading: boolean;
  incidents: any[];
  incidentsTotal: number;
  onOpenIncident: (incidentId: string) => void;
  alertFilters: AlertFiltersState;
  onAlertFiltersChange: React.Dispatch<React.SetStateAction<AlertFiltersState>>;
  alertsLoading: boolean;
  alerts: any[];
  alertsTotal: number;
  onToggleAlertAck: (alert: any, nextAck: boolean) => Promise<void> | void;
  policiesLoading: boolean;
  policies: any[];
  policiesTotal: number;
  onEditPolicy: (rule: any) => void;
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

export function IncidentResponseAdminWorkspace({
  activeTab,
  onActiveTabChange,
  onRefreshActiveTab,
  onOpenCreateIncident,
  onOpenCreatePolicy,
  incidentFilters,
  onIncidentFiltersChange,
  onLoadIncidents,
  licenseeOptions,
  incidentsLoading,
  incidents,
  incidentsTotal,
  onOpenIncident,
  alertFilters,
  onAlertFiltersChange,
  alertsLoading,
  alerts,
  alertsTotal,
  onToggleAlertAck,
  policiesLoading,
  policies,
  policiesTotal,
  onEditPolicy,
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
}: IncidentResponseAdminWorkspaceProps) {
  return (
    <>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Advanced issues</h1>
            <p className="text-sm text-muted-foreground">
              Advanced issue review, alert rules, and customer communications for Platform Admins.
            </p>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <Button variant="outline" onClick={onRefreshActiveTab}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
            {activeTab === "incidents" ? (
              <Button onClick={onOpenCreateIncident}>
                <Plus className="mr-2 h-4 w-4" />
                New incident
              </Button>
            ) : null}
            {activeTab === "policies" ? (
              <Button onClick={onOpenCreatePolicy}>
                <Plus className="mr-2 h-4 w-4" />
                New policy
              </Button>
            ) : null}
          </div>
        </div>

        <IncidentResponseAdminTabs
          activeTab={activeTab}
          onActiveTabChange={onActiveTabChange}
          onRefreshActiveTab={onRefreshActiveTab}
          incidentFilters={incidentFilters}
          onIncidentFiltersChange={onIncidentFiltersChange}
          onLoadIncidents={onLoadIncidents}
          licenseeOptions={licenseeOptions}
          incidentsLoading={incidentsLoading}
          incidents={incidents}
          incidentsTotal={incidentsTotal}
          onOpenIncident={onOpenIncident}
          alertFilters={alertFilters}
          onAlertFiltersChange={onAlertFiltersChange}
          alertsLoading={alertsLoading}
          alerts={alerts}
          alertsTotal={alertsTotal}
          onToggleAlertAck={onToggleAlertAck}
          policiesLoading={policiesLoading}
          policies={policies}
          policiesTotal={policiesTotal}
          onEditPolicy={onEditPolicy}
        />
      </div>

      <IncidentResponseAdminDialogs
        newIncidentOpen={newIncidentOpen}
        onNewIncidentOpenChange={onNewIncidentOpenChange}
        newIncident={newIncident}
        onNewIncidentChange={onNewIncidentChange}
        creatingIncident={creatingIncident}
        onCreateIncident={onCreateIncident}
        licensees={licensees}
        policyDialogOpen={policyDialogOpen}
        onPolicyDialogOpenChange={onPolicyDialogOpenChange}
        editingPolicy={editingPolicy}
        policyForm={policyForm}
        onPolicyFormChange={onPolicyFormChange}
        policySaving={policySaving}
        onSavePolicy={onSavePolicy}
      />
    </>
  );
}
