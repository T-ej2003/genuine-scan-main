import React from "react";
import { Link } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { RefreshCw, Search, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import {
  decisionOutcomeTone,
  decisionRiskTone,
  decisionTrustTone,
  titleCaseDecisionValue,
} from "@/lib/verification-decision";
import {
  ALERT_TYPE_LABEL,
  RULE_TYPE_LABEL,
  SEVERITY_TONE,
  STATUS_TONE,
  type AlertFiltersState,
  type IncidentFiltersState,
  type LicenseeLite,
} from "@/features/ir/types";

type IncidentResponseAdminTabsProps = {
  activeTab: "incidents" | "alerts" | "policies";
  onActiveTabChange: (value: "incidents" | "alerts" | "policies") => void;
  onRefreshActiveTab: () => Promise<void> | void;
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
};

export function IncidentResponseAdminTabs({
  activeTab,
  onActiveTabChange,
  onRefreshActiveTab,
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
}: IncidentResponseAdminTabsProps) {
  return (
    <Tabs value={activeTab} onValueChange={(value) => onActiveTabChange(value as "incidents" | "alerts" | "policies")}>
      <TabsList className="grid w-full grid-cols-3">
        <TabsTrigger value="incidents">Incidents</TabsTrigger>
        <TabsTrigger value="alerts">Policy alerts</TabsTrigger>
        <TabsTrigger value="policies">Policies</TabsTrigger>
      </TabsList>

      <TabsContent value="incidents" className="space-y-4">
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search code, description, or reporter details..."
                  value={incidentFilters.search}
                  onChange={(event) => onIncidentFiltersChange((previous) => ({ ...previous, search: event.target.value }))}
                  className="pl-9"
                  onKeyDown={(event) => {
                    if (event.key === "Enter") void onLoadIncidents();
                  }}
                />
              </div>

              <Select
                value={incidentFilters.status}
                onValueChange={(value) => onIncidentFiltersChange((previous) => ({ ...previous, status: value }))}
              >
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All status</SelectItem>
                  <SelectItem value="NEW">NEW</SelectItem>
                  <SelectItem value="TRIAGE">TRIAGE</SelectItem>
                  <SelectItem value="INVESTIGATING">INVESTIGATING</SelectItem>
                  <SelectItem value="CONTAINMENT">CONTAINMENT</SelectItem>
                  <SelectItem value="ERADICATION">ERADICATION</SelectItem>
                  <SelectItem value="RECOVERY">RECOVERY</SelectItem>
                  <SelectItem value="CLOSED">CLOSED</SelectItem>
                  <SelectItem value="REOPENED">REOPENED</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={incidentFilters.severity}
                onValueChange={(value) => onIncidentFiltersChange((previous) => ({ ...previous, severity: value }))}
              >
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severity</SelectItem>
                  <SelectItem value="LOW">LOW</SelectItem>
                  <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                  <SelectItem value="HIGH">HIGH</SelectItem>
                  <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={incidentFilters.priority}
                onValueChange={(value) => onIncidentFiltersChange((previous) => ({ ...previous, priority: value }))}
              >
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Priority" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="P1">P1</SelectItem>
                  <SelectItem value="P2">P2</SelectItem>
                  <SelectItem value="P3">P3</SelectItem>
                  <SelectItem value="P4">P4</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={incidentFilters.licenseeId}
                onValueChange={(value) => onIncidentFiltersChange((previous) => ({ ...previous, licenseeId: value }))}
              >
                <SelectTrigger className="w-[220px]">
                  <SelectValue placeholder="Licensee" />
                </SelectTrigger>
                <SelectContent>
                  {licenseeOptions.map((licensee) => (
                    <SelectItem key={licensee.id} value={licensee.id}>
                      {licensee.id === "all" ? "All licensees" : `${licensee.name} (${licensee.prefix})`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardHeader>
          <CardContent>
            {incidentsLoading ? (
              <div className="text-sm text-muted-foreground">Loading incidents...</div>
            ) : incidents.length === 0 ? (
              <div className="rounded-lg border p-6 text-sm text-muted-foreground">No incidents match your filters.</div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ID</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Licensee</TableHead>
                      <TableHead>Code</TableHead>
                      <TableHead>Verifier</TableHead>
                      <TableHead>Assignee</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {incidents.map((row) => (
                      <TableRow key={row.id} className="cursor-pointer" onClick={() => onOpenIncident(row.id)}>
                        <TableCell className="text-xs" title={row.id}>
                          <div className="font-semibold">{friendlyReferenceLabel(row.id, "Case")}</div>
                          <div className="font-mono text-[10px] text-muted-foreground">#{shortRawReference(row.id, 8)}</div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={STATUS_TONE[row.status] || "border-slate-200 bg-slate-50 text-slate-700"}>
                            {row.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={SEVERITY_TONE[row.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                            {row.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium">{row.priority}</TableCell>
                        <TableCell className="text-sm">{row.licensee ? `${row.licensee.name} (${row.licensee.prefix})` : "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{row.qrCodeValue || "—"}</TableCell>
                        <TableCell className="space-y-1">
                          {row.latestDecision ? (
                            <>
                              <Badge className={decisionOutcomeTone(row.latestDecision.outcome)}>
                                {titleCaseDecisionValue(row.latestDecision.outcome)}
                              </Badge>
                              <div className="flex flex-wrap gap-1">
                                <Badge className={decisionRiskTone(row.latestDecision.riskBand)}>
                                  {titleCaseDecisionValue(row.latestDecision.riskBand)}
                                </Badge>
                                <Badge className={decisionTrustTone(row.latestDecision.customerTrustReviewState)}>
                                  {titleCaseDecisionValue(row.latestDecision.customerTrustReviewState)}
                                </Badge>
                              </div>
                            </>
                          ) : (
                            <span className="text-xs text-muted-foreground">No verifier decision</span>
                          )}
                        </TableCell>
                        <TableCell className="text-sm">{row.assignedToUser?.name || row.assignedToUser?.email || "Unassigned"}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {row.createdAt ? formatDistanceToNow(new Date(row.createdAt), { addSuffix: true }) : "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <div className="mt-3 text-xs text-muted-foreground">Showing {incidents.length} of {incidentsTotal}.</div>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="alerts" className="space-y-4">
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center">
              <Select
                value={alertFilters.acknowledged}
                onValueChange={(value) => onAlertFiltersChange((previous) => ({ ...previous, acknowledged: value }))}
              >
                <SelectTrigger className="w-[200px]">
                  <SelectValue placeholder="Acknowledged" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false">Unacknowledged</SelectItem>
                  <SelectItem value="true">Acknowledged</SelectItem>
                  <SelectItem value="all">All</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={alertFilters.severity}
                onValueChange={(value) => onAlertFiltersChange((previous) => ({ ...previous, severity: value }))}
              >
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severity</SelectItem>
                  <SelectItem value="LOW">LOW</SelectItem>
                  <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                  <SelectItem value="HIGH">HIGH</SelectItem>
                  <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={alertFilters.alertType}
                onValueChange={(value) => onAlertFiltersChange((previous) => ({ ...previous, alertType: value }))}
              >
                <SelectTrigger className="w-[220px]">
                  <SelectValue placeholder="Alert type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All types</SelectItem>
                  <SelectItem value="POLICY_RULE">POLICY_RULE</SelectItem>
                  <SelectItem value="MULTI_SCAN">MULTI_SCAN</SelectItem>
                  <SelectItem value="GEO_DRIFT">GEO_DRIFT</SelectItem>
                  <SelectItem value="VELOCITY_SPIKE">VELOCITY_SPIKE</SelectItem>
                  <SelectItem value="AUTO_BLOCK_QR">AUTO_BLOCK_QR</SelectItem>
                  <SelectItem value="AUTO_BLOCK_BATCH">AUTO_BLOCK_BATCH</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={alertFilters.licenseeId}
                onValueChange={(value) => onAlertFiltersChange((previous) => ({ ...previous, licenseeId: value }))}
              >
                <SelectTrigger className="w-[220px]">
                  <SelectValue placeholder="Licensee" />
                </SelectTrigger>
                <SelectContent>
                  {licenseeOptions.map((licensee) => (
                    <SelectItem key={licensee.id} value={licensee.id}>
                      {licensee.id === "all" ? "All licensees" : `${licensee.name} (${licensee.prefix})`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardHeader>
          <CardContent>
            {alertsLoading ? (
              <div className="text-sm text-muted-foreground">Loading alerts...</div>
            ) : alerts.length === 0 ? (
              <div className="rounded-lg border p-6 text-sm text-muted-foreground">No policy alerts match your filters.</div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Licensee</TableHead>
                      <TableHead>Code</TableHead>
                      <TableHead>Message</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>
                          <Badge variant="outline" className={SEVERITY_TONE[alert.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm font-medium">{ALERT_TYPE_LABEL[alert.alertType] || alert.alertType}</TableCell>
                        <TableCell className="text-sm">{alert.licensee ? `${alert.licensee.name} (${alert.licensee.prefix})` : "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{alert.qrCode?.code || "—"}</TableCell>
                        <TableCell className="text-sm">{alert.message}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {alert.createdAt ? formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true }) : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          {alert.acknowledgedAt ? (
                            <Button size="sm" variant="outline" onClick={() => onToggleAlertAck(alert, false)}>
                              Unack
                            </Button>
                          ) : (
                            <Button size="sm" onClick={() => onToggleAlertAck(alert, true)}>
                              Acknowledge
                            </Button>
                          )}
                          {alert.incidentId ? (
                            <Button size="sm" variant="ghost" className="ml-2" asChild>
                              <Link to={`/ir/incidents/${alert.incidentId}`}>Open</Link>
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <div className="mt-3 text-xs text-muted-foreground">Showing {alerts.length} of {alertsTotal}.</div>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="policies" className="space-y-4">
        <Card>
          <CardHeader className="pb-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <ShieldAlert className="h-4 w-4" />
              Policy rules are evaluated on scans and can auto-create incidents.
            </div>
          </CardHeader>
          <CardContent>
            {policiesLoading ? (
              <div className="text-sm text-muted-foreground">Loading policies...</div>
            ) : policies.length === 0 ? (
              <div className="rounded-lg border p-6 text-sm text-muted-foreground">No policy rules configured.</div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Threshold</TableHead>
                      <TableHead>Window</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Active</TableHead>
                      <TableHead>Auto incident</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead>Updated</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell className="font-medium">{rule.name}</TableCell>
                        <TableCell className="text-sm">{RULE_TYPE_LABEL[rule.ruleType] || rule.ruleType}</TableCell>
                        <TableCell className="text-sm">{rule.threshold}</TableCell>
                        <TableCell className="text-sm">{rule.windowMinutes} min</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={SEVERITY_TONE[rule.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                            {rule.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">{rule.isActive ? "Yes" : "No"}</TableCell>
                        <TableCell className="text-sm">{rule.autoCreateIncident ? "Yes" : "No"}</TableCell>
                        <TableCell className="text-sm">{rule.licensee ? `${rule.licensee.name} (${rule.licensee.prefix})` : "All"}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {rule.updatedAt ? formatDistanceToNow(new Date(rule.updatedAt), { addSuffix: true }) : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button size="sm" variant="outline" onClick={() => onEditPolicy(rule)}>
                            Edit
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <div className="mt-3 text-xs text-muted-foreground">Showing {policies.length} of {policiesTotal}.</div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
