import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { cn } from '@/lib/utils';

interface QRStatusChartProps {
  data: {
    dormant: number;
    allocated: number;
    printed: number;
    scanned: number;
  };
  selectedStatus?: "all" | "dormant" | "allocated" | "printed" | "scanned";
  onStatusSelect?: (status: "all" | "dormant" | "allocated" | "printed" | "scanned") => void;
}

type ChartStatus = "dormant" | "allocated" | "printed" | "scanned";

export function QRStatusChart({ data, selectedStatus = "all", onStatusSelect }: QRStatusChartProps) {
  const chartData = [
    { key: "dormant" as ChartStatus, name: 'Dormant', value: data.dormant, color: 'hsl(215, 16%, 47%)' },
    { key: "allocated" as ChartStatus, name: 'Allocated', value: data.allocated, color: 'hsl(199, 89%, 48%)' },
    { key: "printed" as ChartStatus, name: 'Printed', value: data.printed, color: 'hsl(38, 92%, 50%)' },
    { key: "scanned" as ChartStatus, name: 'Redeemed', value: data.scanned, color: 'hsl(160, 84%, 39%)' },
  ];
  const total = chartData.reduce((acc, row) => acc + row.value, 0);

  return (
    <Card className="animate-fade-in">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">QR Code Status Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
                onClick={(entry: any) => {
                  const key = entry?.key as ChartStatus | undefined;
                  if (!key || !onStatusSelect) return;
                  onStatusSelect(selectedStatus === key ? "all" : key);
                }}
              >
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.color}
                    opacity={selectedStatus === "all" || selectedStatus === entry.key ? 1 : 0.25}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px',
                }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onStatusSelect?.("all")}
            className={cn(
              "rounded-md border px-2 py-1 text-xs transition-colors",
              selectedStatus === "all"
                ? "bg-primary/10 border-primary/40 text-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            All ({total.toLocaleString()})
          </button>
          {chartData.map((item) => {
            const pct = total > 0 ? Math.round((item.value / total) * 100) : 0;
            const active = selectedStatus === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => onStatusSelect?.(active ? "all" : item.key)}
                className={cn(
                  "rounded-md border px-2 py-1 text-xs transition-colors",
                  active
                    ? "bg-primary/10 border-primary/40 text-primary"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {item.name} {item.value.toLocaleString()} ({pct}%)
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
