import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDistanceToNow } from "date-fns";
import { Activity, Building2, FileText, Printer, UserPlus } from "lucide-react";
import { AuditLog } from "@/types";
import { Button } from "@/components/ui/button";

interface RecentActivityCardProps {
  logs: AuditLog[];
  title?: string;
  emptyMessage?: string;
  onViewAll?: () => void;
}

const actionIcons: Record<string, React.ElementType> = {
  CREATE_LICENSEE: Building2,
  CREATE_LICENSEE_WITH_ADMIN: Building2,
  CREATE_BATCH: FileText,
  CREATE_PRODUCT_BATCH: FileText,
  ASSIGN_MANUFACTURER: UserPlus,
  ASSIGN_PRODUCT_BATCH_MANUFACTURER: UserPlus,
  CONFIRM_PRINT: Printer,
  DOWNLOAD_PRINT_PACK: Printer,
  DIRECT_PRINT_TOKEN_ISSUED: Printer,
  PRINTED: Printer,
};

const actionLabels: Record<string, string> = {
  CREATE_LICENSEE: "Created licensee",
  CREATE_LICENSEE_WITH_ADMIN: "Created licensee",
  CREATE_BATCH: "Created batch",
  CREATE_PRODUCT_BATCH: "Created product batch",
  ASSIGN_MANUFACTURER: "Assigned manufacturer",
  ASSIGN_PRODUCT_BATCH_MANUFACTURER: "Assigned manufacturer",
  CONFIRM_PRINT: "Confirmed print",
  DOWNLOAD_PRINT_PACK: "Downloaded print pack",
  DIRECT_PRINT_TOKEN_ISSUED: "Issued direct-print token",
  PRINTED: "Printed",
};

const formatDetails = (details: any) => {
  if (!details) return "";
  if (typeof details === "string") return details;
  try {
    const str = JSON.stringify(details);
    return str.length > 120 ? `${str.slice(0, 117)}…` : str;
  } catch {
    return "";
  }
};

export function RecentActivityCard({
  logs,
  title = "Recent Activity",
  emptyMessage = "No recent activity.",
  onViewAll,
}: RecentActivityCardProps) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  const recent = safeLogs.slice(0, 5);

  return (
    <Card className="animate-fade-in">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-lg font-semibold">{title}</CardTitle>
        {onViewAll && recent.length > 0 && (
          <Button variant="ghost" size="sm" onClick={onViewAll}>
            View all
          </Button>
        )}
      </CardHeader>

      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground">{emptyMessage}</p>
        ) : (
          <div className="space-y-4">
            {recent.map((log) => {
              const Icon = actionIcons[String(log.action)] || Activity;
              const label = actionLabels[String(log.action)] || String(log.action || "Activity");
              const details = formatDetails(log.details);
              const who = log.userId ? `${log.userId.slice(0, 8)}…` : "System";
              const when = log.createdAt ? new Date(log.createdAt) : new Date();

              return (
                <div key={log.id} className="flex items-start gap-4">
                  <div className="p-2 rounded-lg bg-muted">
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{label}</p>
                    {details && <p className="text-xs text-muted-foreground truncate">{details}</p>}
                    <p className="text-xs text-muted-foreground">
                      {who} • {formatDistanceToNow(when, { addSuffix: true })}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
