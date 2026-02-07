import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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

type LicenseeOption = { id: string; name: string; prefix: string };

type RequestRow = {
  id: string;
  licenseeId: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
  quantity?: number | null;
  startNumber?: number | null;
  endNumber?: number | null;
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
  const { toast } = useToast();
  const { user } = useAuth();

  const isSuper = user?.role === "super_admin";
  const isLicensee = user?.role === "licensee_admin";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [licensees, setLicensees] = useState<LicenseeOption[]>([]);
  const [licenseeFilter, setLicenseeFilter] = useState<string>("");

  // create request form (licensee admin)
  const [quantity, setQuantity] = useState<number>(1000);
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

    setLoading(true);
    try {
      const res = await apiClient.createQrAllocationRequest({
        quantity,
        note: note.trim() || undefined,
      });
      if (!res.success) {
        toast({ title: "Request failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Requested", description: "Your request is now in the approval queue." });
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

    setLoading(true);
    try {
      const res = await apiClient.approveQrAllocationRequest(activeReq.id, {
        decisionNote: decisionNote.trim() || undefined,
      });
      if (!res.success) {
        const raw = (res.error || "Error").toLowerCase();
        const isBusy = raw.includes("busy") || raw.includes("retry") || raw.includes("conflict");
        toast({
          title: isBusy ? "Batch busy" : "Approve failed",
          description: isBusy ? "Please retry — batch busy." : res.error || "Error",
          variant: "destructive",
        });
        return;
      }

      toast({ title: "Approved", description: "QR range allocated to licensee." });
      setApproveOpen(false);
      setActiveReq(null);
      await loadRequests();
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
  const requestQuantity = (r: RequestRow) =>
    r.quantity && r.quantity > 0
      ? r.quantity
      : r.startNumber && r.endNumber
        ? r.endNumber - r.startNumber + 1
        : 0;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">QR Requests</h1>
            <p className="text-muted-foreground">
              {isSuper
                ? "Approve or reject licensee QR allocation requests."
                : "Request new QR codes for your licensee pool."}
            </p>
          </div>

          <Button variant="outline" onClick={loadRequests} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        {isLicensee && (
          <Card>
            <CardHeader className="pb-3">
              <div className="text-sm text-muted-foreground">Request new QR codes</div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Quantity</Label>
                  <Input
                    type="number"
                    value={quantity}
                    onChange={(e) => setQuantity(parseInt(e.target.value || "0", 10))}
                  />
                </div>
                <div className="text-xs text-muted-foreground self-end pb-2">
                  Allocation range is auto-picked from the next available codes after approval.
                </div>
              </div>

              <div className="space-y-2 mt-3">
                <Label>Note (optional)</Label>
                <Input value={note} onChange={(e) => setNote(e.target.value)} />
              </div>

              <div className="flex justify-end mt-4">
                <Button onClick={submitRequest} disabled={loading}>
                  Submit Request
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col md:flex-row md:items-center gap-3">
              <div className="flex items-center gap-2">
                <Label className="text-xs">Status</Label>
                <select
                  className="border rounded px-2 py-1 text-sm bg-background"
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
                  <Label className="text-xs">Licensee</Label>
                  <select
                    className="border rounded px-2 py-1 text-sm bg-background"
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
          </CardHeader>

          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Request</TableHead>
                    {isSuper && <TableHead>Licensee</TableHead>}
                    <TableHead>Status</TableHead>
                    <TableHead>Requested By</TableHead>
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
                      <TableCell colSpan={isSuper ? 7 : 6} className="text-muted-foreground">
                        No requests found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="font-medium">
                              {`${requestQuantity(r)} codes`}
                              {r.startNumber && r.endNumber ? ` (${r.startNumber} -> ${r.endNumber})` : ""}
                            </div>
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
                              <span className="text-muted-foreground">{r.licenseeId}</span>
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
                            {r.status}
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

        {/* Approve Dialog */}
        <Dialog open={approveOpen} onOpenChange={setApproveOpen}>
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Approve Request</DialogTitle>
              <DialogDescription>
                Approve this quantity request. Range allocation is automatic from next available codes.
              </DialogDescription>
            </DialogHeader>

            {!activeReq ? (
              <div className="text-sm text-muted-foreground">No request selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="text-sm text-muted-foreground">
                  Request quantity: <span className="font-medium text-foreground">{requestQuantity(activeReq)}</span>
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
              <DialogTitle>Reject Request</DialogTitle>
              <DialogDescription>Provide an optional reason.</DialogDescription>
            </DialogHeader>

            {!activeReq ? (
              <div className="text-sm text-muted-foreground">No request selected.</div>
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
      </div>
    </DashboardLayout>
  );
}
