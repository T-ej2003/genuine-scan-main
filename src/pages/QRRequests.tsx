import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { APP_PATHS } from "@/app/route-metadata";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { DataTablePagePattern, PageEmptyState, PageSection } from "@/components/page-patterns/PagePatterns";
import { useAuth } from "@/contexts/AuthContext";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import apiClient from "@/lib/api-client";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { DialogEmptyState } from "@/components/ui/dialog-empty-state";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { onMutationEvent } from "@/lib/mutation-events";
import { format } from "date-fns";
import { RefreshCw, Check, X } from "lucide-react";

const LARGE_REQUEST_APPROVAL_THRESHOLD = 25_000;

type LicenseeOption = { id: string; name: string; prefix: string };

type RequestRow = {
  id: string;
  licenseeId: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
  quantity?: number | null;
  batchName?: string | null;
  note?: string | null;
  decisionNote?: string | null;
  createdAt: string;
  approvedAt?: string | null;
  rejectedAt?: string | null;
  requestedByUser?: { id: string; name: string; email: string } | null;
  approvedByUser?: { id: string; name: string; email: string } | null;
  rejectedByUser?: { id: string; name: string; email: string } | null;
  licensee?: { id: string; name: string; prefix: string } | null;
};

export default function QRRequests() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user } = useAuth();
  const progress = useOperationProgress();

  const isSuper = user?.role === "super_admin";
  const isLicensee = user?.role === "licensee_admin";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [licensees, setLicensees] = useState<LicenseeOption[]>([]);
  const [licenseeFilter, setLicenseeFilter] = useState<string>("");

  // create request form (brand admin)
  const [quantity, setQuantity] = useState<number>(1000);
  const [batchName, setBatchName] = useState("");
  const [note, setNote] = useState("");

  // approve/reject dialog
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [activeReq, setActiveReq] = useState<RequestRow | null>(null);
  const [decisionNote, setDecisionNote] = useState("");

  const loadLicensees = async () => {
    if (!isSuper) return;
    const res = await apiClient.getLicensees();
    if (res.success) {
      const list = (res.data as any[]) || [];
      setLicensees(list.map((l) => ({ id: l.id, name: l.name, prefix: l.prefix })));
    }
  };

  const loadRequests = async () => {
    setLoading(true);
    try {
      const res = await apiClient.getQrAllocationRequests({
        status: statusFilter === "all" ? undefined : statusFilter,
        licenseeId: isSuper ? licenseeFilter || undefined : undefined,
      });
      if (!res.success) {
        setRows([]);
        toast({ title: "Failed to load requests", description: res.error || "Error", variant: "destructive" });
        return;
      }
      setRows((Array.isArray(res.data) ? res.data : []) as RequestRow[]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLicensees();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSuper]);

  useEffect(() => {
    loadRequests();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, licenseeFilter]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      loadRequests();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitRequest = async () => {
    if (!isLicensee) return;

    if (!quantity || quantity <= 0) {
      toast({ title: "Invalid quantity", variant: "destructive" });
      return;
    }
    if (!batchName.trim() || batchName.trim().length < 2) {
      toast({ title: "Enter batch name", description: "Batch name is required.", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.createQrAllocationRequest({
        quantity,
        batchName: batchName.trim(),
        note: note.trim() || undefined,
      });
      if (!res.success) {
        toast({ title: "Request failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Requested", description: "Your request is now in the approval queue." });
      setBatchName("");
      setNote("");
      await loadRequests();
    } finally {
      setLoading(false);
    }
  };

  const openApprove = (r: RequestRow) => {
    setActiveReq(r);
    setDecisionNote("");
    setApproveOpen(true);
  };

  const openReject = (r: RequestRow) => {
    setActiveReq(r);
    setDecisionNote("");
    setRejectOpen(true);
  };

  const submitApprove = async () => {
    if (!activeReq) return;
    const qty = requestQuantity(activeReq);
    const showApprovalProgress = qty >= LARGE_REQUEST_APPROVAL_THRESHOLD;

    if (showApprovalProgress) {
      progress.start({
        title: "Approving allocation request",
        description: "Checking the request and assigning QR labels to this brand.",
        phaseLabel: "Approval",
        detail: `Assigning ${qty.toLocaleString()} QR labels.`,
        mode: "simulated",
        initialValue: 14,
      });
    }

    setLoading(true);
    try {
      const res = await apiClient.approveQrAllocationRequest(activeReq.id, {
        decisionNote: decisionNote.trim() || undefined,
      });
      if (!res.success) {
        if (showApprovalProgress) progress.close();
        const raw = (res.error || "Error").toLowerCase();
        const isBusy = raw.includes("busy") || raw.includes("retry") || raw.includes("conflict");
        toast({
          title: isBusy ? "Batch busy" : "Approve failed",
          description: isBusy ? "Please retry — batch busy." : res.error || "Error",
          variant: "destructive",
        });
        return;
      }

      if (showApprovalProgress) {
        await progress.complete(`Approved request and assigned ${qty.toLocaleString()} QR labels.`);
      }
      toast({ title: "Approved", description: "QR labels are now available to the brand." });
      setApproveOpen(false);
      setActiveReq(null);
      await loadRequests();
    } catch (e: any) {
      if (showApprovalProgress) progress.close();
      toast({ title: "Approve failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const submitReject = async () => {
    if (!activeReq) return;
    setLoading(true);
    try {
      const res = await apiClient.rejectQrAllocationRequest(activeReq.id, {
        decisionNote: decisionNote.trim() || undefined,
      });
      if (!res.success) {
        toast({ title: "Reject failed", description: res.error || "Error", variant: "destructive" });
        return;
      }
      toast({ title: "Rejected", description: "Request rejected." });
      setRejectOpen(false);
      setActiveReq(null);
      await loadRequests();
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => rows, [rows]);
  const requestQuantity = (r: RequestRow) => (r.quantity && r.quantity > 0 ? r.quantity : 0);

  return (
    <DashboardLayout>
      <DataTablePagePattern
        eyebrow={isSuper ? "Approval queue" : "Inventory request"}
        title="QR Requests"
        description={
          isSuper
            ? "Review and approve QR label requests from brand teams."
            : "Request QR labels for a new garment batch or upcoming production run."
        }
        actions={
          <Button variant="outline" onClick={loadRequests} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        }
        filters={
          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <div className="flex items-center gap-2">
              <Label className="text-xs">Status</Label>
              <select
                className="rounded-md border bg-background px-2 py-1 text-sm"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All</option>
                <option value="PENDING">Pending</option>
                <option value="APPROVED">Approved</option>
                <option value="REJECTED">Rejected</option>
              </select>
            </div>

            {isSuper && (
              <div className="flex items-center gap-2">
                <Label className="text-xs">Brand</Label>
                <select
                  className="rounded-md border bg-background px-2 py-1 text-sm"
                  value={licenseeFilter}
                  onChange={(e) => setLicenseeFilter(e.target.value)}
                >
                  <option value="">All</option>
                  {licensees.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} ({l.prefix})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
        }
      >
        {isLicensee && (
          <PageSection
            title="Request QR labels"
            description="Enter the quantity you need and the batch name your team will recognize later."
            action={
              <Button onClick={submitRequest} disabled={loading}>
                Send request
              </Button>
            }
          >
            <Card className="border-0 shadow-none">
              <CardContent className="px-0 pb-0">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Number of QR labels</Label>
                  <Input
                    type="number"
                    value={quantity}
                    onChange={(e) => setQuantity(parseInt(e.target.value || "0", 10))}
                  />
                </div>
                <div className="text-xs text-muted-foreground self-end pb-2">
                  MSCQR assigns the QR labels automatically after approval.
                </div>
              </div>

              <div className="space-y-2 mt-3">
                <Label>Batch name</Label>
                <Input
                  value={batchName}
                  onChange={(e) => setBatchName(e.target.value)}
                  maxLength={120}
                  placeholder="Example: March Retail Rollout"
                />
                <div className="text-xs text-muted-foreground">
                  This becomes the batch label shown across approval, batches, and print workflows.
                </div>
              </div>

              <div className="space-y-2 mt-3">
                <Label>Note (optional)</Label>
                <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional context for the approver" />
              </div>
              </CardContent>
            </Card>
          </PageSection>
        )}

        <PageSection
          title={isSuper ? "Request queue" : "Request history"}
          description={
            isSuper
              ? "Approve or reject requests with clear outcomes for the requesting team."
              : "Track the status of every QR label request for your company."
          }
        >
          <Card className="border-0 shadow-none">
            <CardContent className="px-0 pb-0">
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Request</TableHead>
                    {isSuper && <TableHead>Company</TableHead>}
                    <TableHead>Status</TableHead>
                    <TableHead>Requested by</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Decision</TableHead>
                    {isSuper && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={isSuper ? 7 : 6} className="text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={isSuper ? 7 : 6} className="p-6">
                        <PageEmptyState
                          title={isSuper ? "No QR requests to review" : "No QR requests yet"}
                          description={
                            isSuper
                              ? "New requests will appear here as brand teams submit them."
                              : "Create your first request when you need QR labels for a batch."
                          }
                          actionLabel={!isSuper ? "Open batches" : undefined}
                          onAction={!isSuper ? () => navigate(APP_PATHS.batches) : undefined}
                        />
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="font-medium">{`${requestQuantity(r)} QR labels`}</div>
                            {r.batchName && (
                              <div className="text-xs text-muted-foreground">Batch: {r.batchName}</div>
                            )}
                            {r.note && <div className="text-xs text-muted-foreground">{r.note}</div>}
                          </div>
                        </TableCell>

                        {isSuper && (
                          <TableCell>
                            {r.licensee ? (
                              <div className="space-y-1">
                                <div>{r.licensee.name}</div>
                                <div className="text-xs text-muted-foreground">Prefix: {r.licensee.prefix}</div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">Brand details unavailable</span>
                            )}
                          </TableCell>
                        )}

                        <TableCell>
                          <Badge
                            variant={
                              r.status === "APPROVED"
                                ? "default"
                                : r.status === "REJECTED"
                                ? "secondary"
                                : "outline"
                            }
                          >
                            {r.status === "PENDING" ? "Pending" : r.status === "APPROVED" ? "Approved" : "Rejected"}
                          </Badge>
                        </TableCell>

                        <TableCell>
                          {r.requestedByUser ? (
                            <div className="text-sm">
                              {r.requestedByUser.name}
                              <div className="text-xs text-muted-foreground">{r.requestedByUser.email}</div>
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>

                        <TableCell className="text-muted-foreground">
                          {r.createdAt ? format(new Date(r.createdAt), "MMM d, yyyy") : "—"}
                        </TableCell>

                        <TableCell>
                          {r.status === "APPROVED" && r.approvedByUser ? (
                            <div className="text-xs">
                              Approved by {r.approvedByUser.name}
                              {r.decisionNote && <div className="text-muted-foreground">{r.decisionNote}</div>}
                            </div>
                          ) : r.status === "REJECTED" && r.rejectedByUser ? (
                            <div className="text-xs">
                              Rejected by {r.rejectedByUser.name}
                              {r.decisionNote && <div className="text-muted-foreground">{r.decisionNote}</div>}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>

                        {isSuper && (
                          <TableCell className="text-right">
                            {r.status === "PENDING" ? (
                              <div className="flex justify-end gap-2">
                                <Button size="sm" variant="outline" onClick={() => openApprove(r)}>
                                  <Check className="mr-2 h-4 w-4" />
                                  Approve
                                </Button>
                                <Button size="sm" variant="destructive" onClick={() => openReject(r)}>
                                  <X className="mr-2 h-4 w-4" />
                                  Reject
                                </Button>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
            </CardContent>
          </Card>
        </PageSection>

        {/* Approve Dialog */}
        <Dialog open={approveOpen} onOpenChange={setApproveOpen}>
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Approve QR request</DialogTitle>
              <DialogDescription>
                Approve this request and assign the next available QR labels automatically.
              </DialogDescription>
            </DialogHeader>

            {!activeReq ? (
              <DialogEmptyState
                title="Choose a request to approve"
                description="Close this dialog, reopen Approve from a pending QR request, and MSCQR will restore the request details and decision form."
                onClose={() => setApproveOpen(false)}
              />
            ) : (
              <div className="space-y-4 mt-2">
                <div className="grid gap-2 sm:grid-cols-2">
                  <div className="text-sm text-muted-foreground">
                    Request quantity:{" "}
                    <span className="font-medium text-foreground">{requestQuantity(activeReq)}</span>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Batch name:{" "}
                    <span className="font-medium text-foreground">{activeReq.batchName?.trim() || "—"}</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Decision note (optional)</Label>
                  <Input value={decisionNote} onChange={(e) => setDecisionNote(e.target.value)} />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setApproveOpen(false)} disabled={loading}>
                    Cancel
                  </Button>
                  <Button onClick={submitApprove} disabled={loading}>
                    Approve
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Reject Dialog */}
        <Dialog open={rejectOpen} onOpenChange={setRejectOpen}>
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Reject QR request</DialogTitle>
              <DialogDescription>Add an optional note so the requesting team understands what to change.</DialogDescription>
            </DialogHeader>

            {!activeReq ? (
              <DialogEmptyState
                title="Choose a request to reject"
                description="Close this dialog, reopen Reject from a pending QR request, and MSCQR will restore the request details before you add a decision note."
                onClose={() => setRejectOpen(false)}
              />
            ) : (
              <div className="space-y-4 mt-2">
                <div className="space-y-2">
                  <Label>Decision note (optional)</Label>
                  <Input value={decisionNote} onChange={(e) => setDecisionNote(e.target.value)} />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setRejectOpen(false)} disabled={loading}>
                    Cancel
                  </Button>
                  <Button variant="destructive" onClick={submitReject} disabled={loading}>
                    Reject
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        <OperationProgressDialog
          open={progress.state.open}
          title={progress.state.title}
          description={progress.state.description}
          phaseLabel={progress.state.phaseLabel}
          detail={progress.state.detail}
          speedLabel={progress.state.speedLabel}
          value={progress.state.value}
          indeterminate={progress.state.indeterminate}
        />
      </DataTablePagePattern>
    </DashboardLayout>
  );
}
