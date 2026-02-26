import { useMemo } from "react";
import { CheckCircle2, Monitor, Moon, Sparkles, SunMedium } from "lucide-react";
import { useTheme } from "next-themes";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

type ThemeMode = "light" | "dark" | "system";

type ThemeModeButtonProps = {
  className?: string;
  compact?: boolean;
};

export function ThemeModeButton({ className, compact = false }: ThemeModeButtonProps) {
  const { theme, resolvedTheme, setTheme } = useTheme();

  const currentMode = (theme === "light" || theme === "dark" || theme === "system" ? theme : "system") as ThemeMode;
  const effectiveMode = resolvedTheme === "dark" ? "dark" : "light";

  const currentIcon = useMemo(() => {
    if (currentMode === "system") return Monitor;
    return effectiveMode === "dark" ? Moon : SunMedium;
  }, [currentMode, effectiveMode]);

  const currentLabel = currentMode === "system" ? "Auto" : effectiveMode === "dark" ? "Dark" : "Light";
  const CurrentIcon = currentIcon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          className={cn(
            "group relative overflow-visible rounded-full border border-white/55 bg-white/75 pl-2 pr-2.5 shadow-[0_14px_28px_-20px_rgba(15,23,42,0.45)] dark:border-white/12 dark:bg-slate-950/60",
            compact ? "h-10 gap-2 px-2.5" : "h-10 gap-2.5 px-2.5",
            className
          )}
          aria-label={`Theme mode: ${currentLabel}. Open appearance menu.`}
          title="Theme mode"
        >
          <span className="relative inline-flex h-7 w-7 items-center justify-center rounded-full border border-white/60 bg-white/85 text-slate-700 shadow-[0_8px_14px_-12px_rgba(15,23,42,0.55)] dark:border-white/10 dark:bg-white/5 dark:text-slate-100">
            <CurrentIcon className="h-4 w-4" />
          </span>
          {!compact && (
            <span className="hidden sm:inline-flex items-center gap-1.5 text-xs font-semibold tracking-wide text-foreground/90">
              <Sparkles className="h-3.5 w-3.5 text-emerald-500 dark:text-emerald-300" />
              {currentLabel}
            </span>
          )}
          <span className="pointer-events-none absolute -bottom-1 -right-1 inline-flex items-center gap-1 rounded-full border border-white/60 bg-white/95 px-1.5 py-0.5 text-[10px] font-semibold text-slate-700 shadow-[0_12px_18px_-12px_rgba(15,23,42,0.4)] dark:border-white/10 dark:bg-slate-950/90 dark:text-slate-200">
            {currentMode === "system" ? "SYS" : currentLabel.toUpperCase()}
          </span>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        sideOffset={10}
        className="w-56 rounded-2xl border border-white/35 bg-white/85 p-1.5 shadow-[0_26px_60px_-28px_rgba(2,6,23,0.48)] backdrop-blur-2xl dark:border-white/10 dark:bg-slate-950/85"
      >
        <DropdownMenuLabel className="px-2.5 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">Appearance</span>
            <span className="inline-flex items-center gap-1 rounded-full border border-white/40 bg-white/55 px-2 py-0.5 text-[10px] font-semibold text-foreground/80 dark:border-white/10 dark:bg-white/5 dark:text-foreground/70">
              {currentMode === "system" ? "Auto" : `Manual • ${currentLabel}`}
            </span>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator className="bg-white/30 dark:bg-white/10" />

        <DropdownMenuRadioGroup value={currentMode} onValueChange={(value) => setTheme(value as ThemeMode)}>
          <DropdownMenuRadioItem value="light" className="rounded-xl">
            <SunMedium className="mr-2 h-4 w-4 text-amber-500" />
            Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark" className="rounded-xl">
            <Moon className="mr-2 h-4 w-4 text-indigo-400" />
            Dark
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system" className="rounded-xl">
            <Monitor className="mr-2 h-4 w-4 text-emerald-500" />
            Auto (system)
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>

        <DropdownMenuSeparator className="bg-white/30 dark:bg-white/10" />
        <DropdownMenuItem
          className="rounded-xl text-xs text-muted-foreground focus:text-foreground"
          onClick={() => setTheme(effectiveMode === "dark" ? "light" : "dark")}
        >
          <CheckCircle2 className="mr-2 h-3.5 w-3.5" />
          Quick toggle ({effectiveMode === "dark" ? "to light" : "to dark"})
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
