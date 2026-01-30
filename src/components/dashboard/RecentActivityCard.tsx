import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDistanceToNow } from "date-fns";
import { Activity, Building2, FileText, Printer, UserPlus } from "lucide-react";
import { AuditLog } from "@/types";

interface RecentActivityCardProps {
  logs: AuditLog[];
}

const actionIcons: Record<string, React.ElementType> = {
  CREATE_LICENSEE: Building2,
  CREATE_BATCH: FileText,
  ASSIGN_BATCH: UserPlus,
  CONFIRM_PRINT: Printer,
};

export function RecentActivityCard({ logs }: RecentActivityCardProps) {
  const safeLogs = Array.isArray(logs) ? logs : [];
  const recent = safeLogs.slice(0, 5);

  return (
    <Card className="animate-fade-in">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">Recent Activity</CardTitle>
      </CardHeader>

      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground">No recent activity.</p>
        ) : (
          <div className="space-y-4">
            {recent.map((log) => {
              const Icon = actionIcons[String(log.action)] || Activity;

              return (
                <div key={log.id} className="flex items-start gap-4">
                  <div className="p-2 rounded-lg bg-muted">
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{log.details}</p>
                    <p className="text-xs text-muted-foreground">
                      {log.userName} •{" "}
                      {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
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

