import { useEffect, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, ExternalLink, ScanLine, ShieldCheck } from "lucide-react";

import { APP_PATHS, getNavItemsForRole } from "@/app/route-metadata";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { DialogDescription, DialogTitle } from "@/components/ui/dialog";
import type { UserRole } from "@/types";

type PlatformCommandPaletteProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role?: UserRole | null;
  helpRoute: string;
};

export function PlatformCommandPalette({ open, onOpenChange, role, helpRoute }: PlatformCommandPaletteProps) {
  const navigate = useNavigate();
  const navCommands = useMemo(() => getNavItemsForRole(role), [role]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenChange(!open);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onOpenChange, open]);

  const runCommand = (href: string) => {
    onOpenChange(false);
    navigate(href);
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <DialogTitle className="sr-only">Workspace search</DialogTitle>
      <DialogDescription className="sr-only">Search role-aware MSCQR workspace pages and support surfaces.</DialogDescription>
      <div className="border-b border-mscqr-border bg-mscqr-surface-elevated px-4 py-3">
        <p className="text-sm font-semibold text-mscqr-primary">Workspace search</p>
        <p className="text-xs text-mscqr-secondary">Open the pages available to your role.</p>
      </div>
      <CommandInput placeholder="Search workspace pages, scans, help..." />
      <CommandList className="max-h-[420px]">
        <CommandEmpty>No matching command found.</CommandEmpty>

        <CommandGroup heading="Workspace pages">
          {navCommands.map((command) => (
            <CommandItem
              key={command.href}
              value={`${command.label} ${command.title} ${command.section}`}
              onSelect={() => runCommand(command.href)}
              className="gap-3"
            >
              <command.icon className="h-4 w-4 text-mscqr-accent" />
              <span>{command.label}</span>
              <CommandShortcut>{command.section}</CommandShortcut>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Public and support">
          <CommandItem value="verify garment public verification scan qr label" onSelect={() => runCommand(APP_PATHS.verify)} className="gap-3">
            <ScanLine className="h-4 w-4 text-mscqr-accent" />
            <span>Verify a garment</span>
            <CommandShortcut>Public</CommandShortcut>
          </CommandItem>
          <CommandItem value="help support documentation" onSelect={() => runCommand(helpRoute)} className="gap-3">
            <ShieldCheck className="h-4 w-4 text-mscqr-audit" />
            <span>Open contextual help</span>
            <CommandShortcut>Help</CommandShortcut>
          </CommandItem>
          <CommandItem value="trust security public scanning" onSelect={() => runCommand("/trust")} className="gap-3">
            <ExternalLink className="h-4 w-4 text-mscqr-secondary" />
            <span>Trust & Security</span>
            <CommandShortcut>Public</CommandShortcut>
          </CommandItem>
        </CommandGroup>
      </CommandList>
      <div className="flex items-center justify-between border-t border-mscqr-border bg-mscqr-surface-muted/40 px-4 py-2 text-xs text-mscqr-muted">
        <span>Use arrow keys to move, Enter to open.</span>
        <Link to={APP_PATHS.settings} onClick={() => onOpenChange(false)} className="inline-flex items-center gap-1 hover:text-mscqr-primary">
          Account settings <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
    </CommandDialog>
  );
}
