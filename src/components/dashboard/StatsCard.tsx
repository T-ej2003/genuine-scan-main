import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface StatsCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  subtitle?: string;
  trend?: {
    value: number;
    label: string;
  };
  variant?: 'default' | 'success' | 'warning' | 'info';
  onClick?: () => void;
  ctaLabel?: string;
}

export function StatsCard({
  title,
  value,
  icon: Icon,
  subtitle,
  trend,
  variant = 'default',
  onClick,
  ctaLabel,
}: StatsCardProps) {
  const variantStyles = {
    default: 'bg-primary/10 text-primary',
    success: 'bg-success/10 text-success',
    warning: 'bg-warning/10 text-warning',
    info: 'bg-info/10 text-info',
  };

  const clickable = typeof onClick === "function";
  const valueLabel = typeof value === "number" ? value.toLocaleString() : String(value);

  return (
    <Card
      className={cn(
        "animate-fade-in transition-all",
        clickable ? "cursor-pointer hover:-translate-y-0.5 hover:shadow-md" : ""
      )}
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (!clickable) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick?.();
        }
      }}
    >
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <p className="text-3xl font-bold tracking-tight">{valueLabel}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
            {trend && (
              <p className={cn(
                "text-xs font-medium",
                trend.value >= 0 ? "text-success" : "text-destructive"
              )}>
                {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
              </p>
            )}
            {clickable && ctaLabel && <p className="text-xs font-medium text-primary">{ctaLabel}</p>}
          </div>
          <div className={cn("p-3 rounded-lg", variantStyles[variant])}>
            <Icon className="h-6 w-6" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
