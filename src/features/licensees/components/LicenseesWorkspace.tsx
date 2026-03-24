import React from "react";
import { format } from "date-fns";
import {
  Building2,
  Download,
  Edit,
  Link2,
  MoreHorizontal,
  Plus,
  QrCode,
  Search,
  Send,
  Trash2,
  UserPlus,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { LicenseeRow } from "@/features/licensees/types";

type LicenseesWorkspaceProps = {
  latestInviteLink: string;
  onCopyLatestInviteLink: () => void;
  onDismissLatestInviteLink: () => void;
  onRefresh: () => Promise<void> | void;
  loading: boolean;
  onExportCsv: () => Promise<void> | void;
  onOpenCreateDialog: () => void;
  search: string;
  onSearchChange: (value: string) => void;
  statusFilter: "all" | "active" | "inactive";
  onStatusFilterChange: (value: "all" | "active" | "inactive") => void;
  filtered: LicenseeRow[];
  inviteActionLoadingId: string;
  onOpenAllocateRange: (licensee: LicenseeRow) => void;
  onOpenCreateUser: (licenseeId: string) => void;
  onOpenEdit: (licensee: LicenseeRow) => void;
  onResendAdminInvite: (licensee: LicenseeRow, options?: { copyOnly?: boolean }) => Promise<void> | void;
  onToggleActive: (licensee: LicenseeRow) => Promise<void> | void;
  onHardDelete: (licensee: LicenseeRow) => Promise<void> | void;
};

export function LicenseesWorkspace({
  latestInviteLink,
  onCopyLatestInviteLink,
  onDismissLatestInviteLink,
  onRefresh,
  loading,
  onExportCsv,
  onOpenCreateDialog,
  search,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  filtered,
  inviteActionLoadingId,
  onOpenAllocateRange,
  onOpenCreateUser,
  onOpenEdit,
  onResendAdminInvite,
  onToggleActive,
  onHardDelete,
}: LicenseesWorkspaceProps) {
  return (
    <div className="space-y-6">
      {latestInviteLink ? (
        <Card className="border-emerald-200 bg-emerald-50/60">
          <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-emerald-900">Invite link generated</p>
              <p className="text-xs text-emerald-800">
                Email delivery may be disabled locally. Use this link to onboard the admin securely.
              </p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={onCopyLatestInviteLink}>
                Copy invite link
              </Button>
              <Button variant="ghost" onClick={onDismissLatestInviteLink}>
                Dismiss
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold">Licensees</h1>
          <p className="text-muted-foreground">Manage licensee organizations and code allocations</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={onRefresh} disabled={loading}>
            Refresh
          </Button>

          <Button variant="outline" onClick={onExportCsv}>
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>

          <Button onClick={onOpenCreateDialog}>
            <Plus className="mr-2 h-4 w-4" />
            Add Licensee
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search licensees..."
                value={search}
                onChange={(event) => onSearchChange(event.target.value)}
                className="pl-9"
              />
            </div>

            <Select value={statusFilter} onValueChange={(value) => onStatusFilterChange(value as "all" | "active" | "inactive")}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Status filter" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>

        <CardContent>
          {loading ? (
            <div className="text-sm text-muted-foreground">Loading...</div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Licensee</TableHead>
                    <TableHead>Prefix</TableHead>
                    <TableHead>Admin Access</TableHead>
                    <TableHead>Latest Code Range</TableHead>
                    <TableHead className="text-right">Users</TableHead>
                    <TableHead className="text-right">Batches</TableHead>
                    <TableHead className="text-right">Codes</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-[50px]" />
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {filtered.map((licensee) => {
                    const usersCount = licensee._count?.users ?? 0;
                    const batchesCount = licensee._count?.batches ?? 0;
                    const qrCount = licensee._count?.qrCodes ?? 0;
                    const latest = licensee.latestRange;
                    const latestRangeText = latest ? `${latest.startCode} -> ${latest.endCode}` : "—";
                    const onboarding = licensee.adminOnboarding || null;
                    const onboardingState = onboarding?.state || "UNASSIGNED";
                    const adminEmail = onboarding?.adminUser?.email || onboarding?.pendingInvite?.email || "—";

                    return (
                      <TableRow key={licensee.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                              <Building2 className="h-5 w-5 text-primary" />
                            </div>
                            <div>
                              <p className="font-medium">{licensee.name}</p>
                              <p className="text-xs text-muted-foreground">{licensee.description || "—"}</p>
                            </div>
                          </div>
                        </TableCell>

                        <TableCell>
                          <Badge variant="outline" className="font-mono">
                            {licensee.prefix}
                          </Badge>
                        </TableCell>

                        <TableCell>
                          <div className="space-y-1">
                            <Badge
                              variant="outline"
                              className={
                                onboardingState === "PENDING"
                                  ? "border-amber-200 bg-amber-50 text-amber-700"
                                  : onboardingState === "ACTIVE"
                                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                                    : "border-slate-200 bg-slate-50 text-slate-700"
                              }
                            >
                              {onboardingState}
                            </Badge>
                            <p className="max-w-[220px] truncate text-xs text-muted-foreground">{adminEmail}</p>
                          </div>
                        </TableCell>

                        <TableCell className="font-mono text-xs">{latestRangeText}</TableCell>

                        <TableCell className="text-right">{usersCount}</TableCell>
                        <TableCell className="text-right">{batchesCount}</TableCell>
                        <TableCell className="text-right">{qrCount}</TableCell>

                        <TableCell>
                          <Badge variant={licensee.isActive ? "default" : "secondary"}>
                            {licensee.isActive ? "Active" : "Inactive"}
                          </Badge>
                        </TableCell>

                        <TableCell className="text-muted-foreground">
                          {licensee.createdAt ? format(new Date(licensee.createdAt), "MMM d, yyyy") : "—"}
                        </TableCell>

                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>

                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => onOpenAllocateRange(licensee)}>
                                <QrCode className="mr-2 h-4 w-4" />
                                Allocate Code Range
                              </DropdownMenuItem>

                              <DropdownMenuItem onClick={() => onOpenCreateUser(licensee.id)}>
                                <UserPlus className="mr-2 h-4 w-4" />
                                Create User
                              </DropdownMenuItem>

                              <DropdownMenuItem onClick={() => onOpenEdit(licensee)}>
                                <Edit className="mr-2 h-4 w-4" />
                                Edit
                              </DropdownMenuItem>

                              <DropdownMenuItem
                                disabled={inviteActionLoadingId === licensee.id}
                                onClick={() => onResendAdminInvite(licensee)}
                              >
                                <Send className="mr-2 h-4 w-4" />
                                Resend admin invite
                              </DropdownMenuItem>

                              <DropdownMenuItem
                                disabled={inviteActionLoadingId === licensee.id}
                                onClick={() => onResendAdminInvite(licensee, { copyOnly: true })}
                              >
                                <Link2 className="mr-2 h-4 w-4" />
                                Copy invite link
                              </DropdownMenuItem>

                              <DropdownMenuItem onClick={() => onToggleActive(licensee)}>
                                <Trash2 className="mr-2 h-4 w-4" />
                                {licensee.isActive ? "Deactivate" : "Activate"}
                              </DropdownMenuItem>

                              <DropdownMenuItem className="text-destructive" onClick={() => onHardDelete(licensee)}>
                                <Trash2 className="mr-2 h-4 w-4" />
                                Hard Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}

                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={10} className="text-center text-sm text-muted-foreground">
                        No licensees found.
                      </TableCell>
                    </TableRow>
                  ) : null}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
