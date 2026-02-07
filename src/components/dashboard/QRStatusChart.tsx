import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface QRStatusChartProps {
  data: {
    dormant: number;
    allocated: number;
    printed: number;
    scanned: number;
  };
}

export function QRStatusChart({ data }: QRStatusChartProps) {
  const chartData = [
    { name: 'Dormant', value: data.dormant, color: 'hsl(215, 16%, 47%)' },
    { name: 'Allocated', value: data.allocated, color: 'hsl(199, 89%, 48%)' },
    { name: 'Printed', value: data.printed, color: 'hsl(38, 92%, 50%)' },
    { name: 'Redeemed', value: data.scanned, color: 'hsl(160, 84%, 39%)' },
  ];

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
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
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
      </CardContent>
    </Card>
  );
}
