import { useEffect, useMemo, useState } from "react";
import { Copy, Plus, RefreshCw } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import {
  DataTablePagePattern,
  PageEmptyState,
  PageInlineNotice,
  PageSection,
} from "@/components/page-patterns/PagePatterns";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/AuthContext";
import {
  ManufacturerDetailsDialog,
} from "@/features/manufacturers/components/ManufacturerDetailsDialog";
import { ManufacturerInviteDialog } from "@/features/manufacturers/components/ManufacturerInviteDialog";
import { ManufacturersTable } from "@/features/manufacturers/components/ManufacturersTable";
import { ManufacturerSummaryCards } from "@/features/manufacturers/components/ManufacturerSummaryCards";
import {
  useDeactivateManufacturerMutation,
  useDeleteManufacturerMutation,
  useInviteManufacturerMutation,
  useManufacturerDirectory,
  useManufacturerLicensees,
  useRestoreManufacturerMutation,
} from "@/features/manufacturers/hooks";
import type { ManufacturerInviteFormValues } from "@/features/manufacturers/schemas";
import type { ManufacturerRow } from "@/features/manufacturers/types";
import { useToast } from "@/hooks/use-toast";

type PendingAction =
  | { type: "deactivate"; manufacturer: ManufacturerRow }
  | { type: "restore"; manufacturer: ManufacturerRow }
  | { type: "delete"; manufacturer: ManufacturerRow }
  | null;

export default function ManufacturersPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user } = useAuth();

  const isSuperAdmin = user?.role === "super_admin";
  const fixedLicenseeId = String(user?.licenseeId || "").trim();

  const [search, setSearch] = useState("");
  const [showInactive, setShowInactive] = useState(true);
  const [licenseeFilter, setLicenseeFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [detailsManufacturer, setDetailsManufacturer] = useState<ManufacturerRow | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);

  const licenseesQuery = useManufacturerLicensees(isSuperAdmin);

  useEffect(() => {
    if (!isSuperAdmin) return;
    if (licenseeFilter) return;
    if (!licenseesQuery.data || licenseesQuery.data.length === 0) return;
    setLicenseeFilter(licenseesQuery.data[0].id);
  }, [isSuperAdmin, licenseeFilter, licenseesQuery.data]);

  const effectiveLicenseeId = isSuperAdmin ? licenseeFilter : fixedLicenseeId;
  const hasMissingScope = !isSuperAdmin && !effectiveLicenseeId;
  const canLoadDirectory = !hasMissingScope && (!isSuperAdmin || Boolean(effectiveLicenseeId));

  const directoryQuery = useManufacturerDirectory(effectiveLicenseeId, canLoadDirectory);
  const inviteMutation = useInviteManufacturerMutation();
  const deactivateMutation = useDeactivateManufacturerMutation();
  const restoreMutation = useRestoreManufacturerMutation();
  const deleteMutation = useDeleteManufacturerMutation();

  const manufacturers = directoryQuery.data?.manufacturers || [];
  const statsById = directoryQuery.data?.statsById || {};

  const filteredManufacturers = useMemo(() => {
    const query = search.trim().toLowerCase();

    return manufacturers
      .filter((manufacturer) => (showInactive ? true : manufacturer.isActive))
      .filter((manufacturer) => {
        if (!query) return true;
        return (
          manufacturer.name.toLowerCase().includes(query) ||
          manufacturer.email.toLowerCase().includes(query) ||
          String(manufacturer.location || "").toLowerCase().includes(query)
        );
      });
  }, [manufacturers, search, showInactive]);

  const summary = useMemo(() => {
    let active = 0;
    let inactive = 0;
    let assignedBatches = 0;
    let pendingPrintBatches = 0;

    for (const manufacturer of filteredManufacturers) {
      if (manufacturer.isActive) active += 1;
      else inactive += 1;

      const stats = statsById[manufacturer.id];
      if (!stats) continue;
      assignedBatches += stats.assignedBatches;
      pendingPrintBatches += stats.pendingPrintBatches;
    }

    return {
      total: filteredManufacturers.length,
      active,
      inactive,
      assignedBatches,
      pendingPrintBatches,
    };
  }, [filteredManufacturers, statsById]);

  const refreshDirectory = async () => {
    await Promise.all([
      isSuperAdmin ? licenseesQuery.refetch() : Promise.resolve(),
      canLoadDirectory ? directoryQuery.refetch() : Promise.resolve(),
    ]);
  };

  const openManufacturerBatches = (manufacturer: ManufacturerRow, printState?: "pending" | "printed") => {
    const params = new URLSearchParams();
    params.set("manufacturerId", manufacturer.id);
    params.set("manufacturerName", manufacturer.name);
    if (printState) params.set("printState", printState);
    navigate(`/batches?${params.toString()}`);
  };

  const handleCopyId = async (id: string) => {
    try {
      await navigator.clipboard.writeText(id);
      toast({ title: "Copied", description: "Manufacturer record ID copied to clipboard." });
    } catch {
      toast({
        title: "Copy failed",
        description: "Could not copy the manufacturer record ID.",
        variant: "destructive",
      });
    }
  };

  const handleInvite = async (values: ManufacturerInviteFormValues) => {
    try {
      const result = await inviteMutation.mutateAsync({
        email: values.email,
        name: values.name,
        licenseeId: values.licenseeId,
      });

      if (result.linkAction === "LINKED_EXISTING" || result.linkAction === "ALREADY_LINKED") {
        toast({
          title: result.linkAction === "ALREADY_LINKED" ? "Manufacturer already linked" : "Manufacturer linked",
          description:
            result.linkAction === "ALREADY_LINKED"
              ? `${values.email} is already available under this brand.`
              : `${values.email} was linked without creating a new invite.`,
        });
      } else {
        toast({
          title: "Invite sent",
          description: `Activation and printer setup links were emailed to ${values.email}.`,
        });
      }

      setCreateOpen(false);
    } catch (error) {
      toast({
        title: "Invite failed",
        description: error instanceof Error ? error.message : "Could not invite this manufacturer.",
        variant: "destructive",
      });
    }
  };

  const handlePendingAction = async () => {
    if (!pendingAction) return;

    try {
      if (pendingAction.type === "deactivate") {
        await deactivateMutation.mutateAsync(pendingAction.manufacturer.id);
        toast({
          title: "Manufacturer deactivated",
          description: `${pendingAction.manufacturer.name} is now inactive.`,
        });
      } else if (pendingAction.type === "restore") {
        await restoreMutation.mutateAsync(pendingAction.manufacturer.id);
        toast({
          title: "Manufacturer restored",
          description: `${pendingAction.manufacturer.name} is active again.`,
        });
      } else {
        await deleteMutation.mutateAsync(pendingAction.manufacturer.id);
        toast({
          title: "Manufacturer deleted",
          description: `${pendingAction.manufacturer.name} was permanently removed.`,
        });
        if (detailsManufacturer?.id === pendingAction.manufacturer.id) {
          setDetailsManufacturer(null);
        }
      }
      setPendingAction(null);
    } catch (error) {
      toast({
        title: "Action failed",
        description: error instanceof Error ? error.message : "Could not update this manufacturer.",
        variant: "destructive",
      });
    }
  };

  const filters = (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-1 flex-col gap-3 sm:flex-row">
        <Input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search by manufacturer name, email, or location"
          className="sm:max-w-md"
        />
        <Button variant={showInactive ? "default" : "secondary"} onClick={() => setShowInactive((value) => !value)}>
          {showInactive ? "Showing all" : "Showing active only"}
        </Button>
      </div>

      {isSuperAdmin ? (
        <Select value={licenseeFilter} onValueChange={setLicenseeFilter}>
          <SelectTrigger className="w-full sm:w-[280px]">
            <SelectValue placeholder="Choose a brand" />
          </SelectTrigger>
          <SelectContent>
            {licenseesQuery.data?.map((licensee) => (
              <SelectItem key={licensee.id} value={licensee.id}>
                {licensee.name} ({licensee.prefix})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : null}
    </div>
  );

  const actions = (
    <>
      <Button variant="outline" onClick={() => void refreshDirectory()} disabled={directoryQuery.isFetching || licenseesQuery.isFetching}>
        <RefreshCw className="mr-2 h-4 w-4" />
        {directoryQuery.isFetching || licenseesQuery.isFetching ? "Refreshing..." : "Refresh"}
      </Button>
      <Button onClick={() => setCreateOpen(true)} disabled={isSuperAdmin && !effectiveLicenseeId}>
        <Plus className="mr-2 h-4 w-4" />
        Invite manufacturer
      </Button>
    </>
  );

  return (
    <DashboardLayout>
      <DataTablePagePattern
        eyebrow={isSuperAdmin ? "Operations" : "Your company"}
        title="Manufacturers"
        description={
          isSuperAdmin
            ? "Review manufacturer readiness and batch workload for the selected brand."
            : "Keep manufacturer admins active, assigned, and ready to print."
        }
        actions={actions}
        filters={filters}
      >
        {hasMissingScope ? (
          <PageInlineNotice
            variant="destructive"
            title="Missing brand workspace"
            description="Your account is not linked to a brand yet. Ask a Platform Admin to update your access."
          />
        ) : null}

        {isSuperAdmin && !licenseeFilter && !licenseesQuery.isLoading ? (
          <PageInlineNotice
            title="Choose a brand"
            description="Pick a brand above to load its manufacturer directory."
          />
        ) : null}

        {directoryQuery.error ? (
          <PageInlineNotice
            variant="destructive"
            title="Could not load manufacturers"
            description={directoryQuery.error instanceof Error ? directoryQuery.error.message : "Please refresh and try again."}
          />
        ) : null}

        <ManufacturerSummaryCards {...summary} />

        <PageSection
          title="Manufacturer directory"
          description="Open a manufacturer to review contact details, active workload, and recent assigned batches."
          action={
            filteredManufacturers.length > 0 ? (
              <Button variant="outline" onClick={() => filteredManufacturers[0] && setDetailsManufacturer(filteredManufacturers[0])}>
                <Copy className="mr-2 h-4 w-4" />
                Review first record
              </Button>
            ) : null
          }
        >
          {directoryQuery.isLoading ? (
            <div className="text-sm text-muted-foreground">Loading manufacturers...</div>
          ) : filteredManufacturers.length === 0 ? (
            <PageEmptyState
              title={manufacturers.length === 0 ? "No manufacturers added yet" : "No manufacturers match this view"}
              description={
                manufacturers.length === 0
                  ? "Invite a manufacturer admin to start assigning batches and printing."
                  : "Adjust the search or status filter to see more manufacturers."
              }
              actionLabel={manufacturers.length === 0 ? "Invite manufacturer" : undefined}
              onAction={manufacturers.length === 0 ? () => setCreateOpen(true) : undefined}
            />
          ) : (
            <ManufacturersTable
              rows={filteredManufacturers}
              statsById={statsById}
              onViewDetails={setDetailsManufacturer}
              onOpenBatches={openManufacturerBatches}
              onCopyId={handleCopyId}
              onDeactivate={(manufacturer) => setPendingAction({ type: "deactivate", manufacturer })}
              onRestore={(manufacturer) => setPendingAction({ type: "restore", manufacturer })}
              onDelete={(manufacturer) => setPendingAction({ type: "delete", manufacturer })}
            />
          )}
        </PageSection>

        <ManufacturerInviteDialog
          open={createOpen}
          onOpenChange={setCreateOpen}
          isSuperAdmin={isSuperAdmin}
          licensees={licenseesQuery.data || []}
          defaultLicenseeId={effectiveLicenseeId}
          submitting={inviteMutation.isPending}
          onSubmit={handleInvite}
        />

        <ManufacturerDetailsDialog
          open={Boolean(detailsManufacturer)}
          onOpenChange={(open) => {
            if (!open) setDetailsManufacturer(null);
          }}
          manufacturer={detailsManufacturer}
          stats={detailsManufacturer ? statsById[detailsManufacturer.id] : undefined}
          onCopyId={handleCopyId}
          onOpenBatches={openManufacturerBatches}
        />

        <AlertDialog open={Boolean(pendingAction)} onOpenChange={(open) => !open && setPendingAction(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                {pendingAction?.type === "delete"
                  ? "Delete manufacturer permanently?"
                  : pendingAction?.type === "deactivate"
                    ? "Deactivate manufacturer?"
                    : "Restore manufacturer?"}
              </AlertDialogTitle>
              <AlertDialogDescription>
                {pendingAction?.type === "delete"
                  ? "This permanently removes the manufacturer record. Only continue if there are no linked batches or operational records that still need it."
                  : pendingAction?.type === "deactivate"
                    ? "The manufacturer admin will lose active access until you restore the account."
                    : "This will make the manufacturer admin active again and ready for assignments."}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={() => void handlePendingAction()}>
                {pendingAction?.type === "delete"
                  ? "Delete permanently"
                  : pendingAction?.type === "deactivate"
                    ? "Deactivate"
                    : "Restore"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DataTablePagePattern>
    </DashboardLayout>
  );
}
