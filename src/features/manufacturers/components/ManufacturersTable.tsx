import { Activity, Copy, Eye, Factory, MoreHorizontal, PackageCheck, Power, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

import {
  formatAssignmentTimestamp,
  manufacturerOperationalStatus,
  type ManufacturerRow,
  type ManufacturerStats,
} from "@/features/manufacturers/types";

type ManufacturersTableProps = {
  rows: ManufacturerRow[];
  statsById: Record<string, ManufacturerStats>;
  onViewDetails: (manufacturer: ManufacturerRow) => void;
  onOpenBatches: (manufacturer: ManufacturerRow, printState?: "pending" | "printed") => void;
  onCopyId: (id: string) => void;
  onDeactivate: (manufacturer: ManufacturerRow) => void;
  onRestore: (manufacturer: ManufacturerRow) => void;
  onDelete: (manufacturer: ManufacturerRow) => void;
};

export function ManufacturersTable({
  rows,
  statsById,
  onViewDetails,
  onOpenBatches,
  onCopyId,
  onDeactivate,
  onRestore,
  onDelete,
}: ManufacturersTableProps) {
  return (
    <div className="rounded-2xl border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Manufacturer</TableHead>
            <TableHead>Admin contact</TableHead>
            <TableHead>Current load</TableHead>
            <TableHead>Print status</TableHead>
            <TableHead>Last assignment</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-[80px]" />
          </TableRow>
        </TableHeader>

        <TableBody>
          {rows.map((manufacturer) => {
            const stats = statsById[manufacturer.id];
            const operationalStatus = manufacturerOperationalStatus(stats);

            return (
              <TableRow key={manufacturer.id}>
                <TableCell>
                  <div className="flex items-center gap-3">
                    <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/10">
                      <Factory className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <button type="button" className="font-medium text-left hover:underline" onClick={() => onViewDetails(manufacturer)}>
                        {manufacturer.name}
                      </button>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {manufacturer.location || "Location not added"}
                      </div>
                    </div>
                  </div>
                </TableCell>

                <TableCell className="text-sm text-muted-foreground">
                  <div className="font-medium text-foreground">{manufacturer.email}</div>
                  <div className="mt-1">
                    {manufacturer.website ? (
                      <a className="text-primary hover:underline" href={manufacturer.website} rel="noreferrer" target="_blank">
                        Website
                      </a>
                    ) : (
                      "No website"
                    )}
                  </div>
                </TableCell>

                <TableCell>
                  <div className="text-sm font-medium">{stats?.assignedBatches || 0} active batches</div>
                  <div className="mt-1 text-xs text-muted-foreground">{stats?.assignedCodes || 0} codes assigned</div>
                  <Button size="sm" variant="outline" className="mt-3" onClick={() => onOpenBatches(manufacturer)}>
                    Open batches
                  </Button>
                </TableCell>

                <TableCell>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs text-emerald-800"
                      onClick={() => onOpenBatches(manufacturer, "printed")}
                    >
                      <Activity className="h-3.5 w-3.5" />
                      {stats?.printedBatches || 0} printed
                    </button>
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs text-amber-800"
                      onClick={() => onOpenBatches(manufacturer, "pending")}
                    >
                      <Activity className="h-3.5 w-3.5" />
                      {stats?.pendingPrintBatches || 0} pending
                    </button>
                  </div>
                </TableCell>

                <TableCell className="text-sm text-muted-foreground">
                  {formatAssignmentTimestamp(stats?.lastBatchAt)}
                </TableCell>

                <TableCell>
                  <div className="flex flex-col gap-2">
                    <Badge variant={manufacturer.isActive ? "default" : "secondary"}>
                      {manufacturer.isActive ? "Active" : "Inactive"}
                    </Badge>
                    <Badge variant={operationalStatus.tone}>{operationalStatus.label}</Badge>
                  </div>
                </TableCell>

                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    <Button size="sm" variant="outline" onClick={() => onViewDetails(manufacturer)}>
                      <Eye className="mr-2 h-4 w-4" />
                      View
                    </Button>

                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label={`Open actions for ${manufacturer.name}`}>
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>

                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => onCopyId(manufacturer.id)}>
                          <Copy className="mr-2 h-4 w-4" />
                          Copy record ID
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onOpenBatches(manufacturer)}>
                          <PackageCheck className="mr-2 h-4 w-4" />
                          Open batches
                        </DropdownMenuItem>
                        {manufacturer.isActive ? (
                          <DropdownMenuItem onClick={() => onDeactivate(manufacturer)}>
                            <Power className="mr-2 h-4 w-4" />
                            Deactivate
                          </DropdownMenuItem>
                        ) : (
                          <DropdownMenuItem onClick={() => onRestore(manufacturer)}>
                            <Power className="mr-2 h-4 w-4" />
                            Restore
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem className="text-destructive" onClick={() => onDelete(manufacturer)}>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete permanently
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
