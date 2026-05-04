import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { motion, useReducedMotion } from "framer-motion";
import { useTheme } from "next-themes";
import { Activity, ChevronDown, CircleHelp, Command, LogOut, Menu, Moon, Printer, Settings, Sun } from "lucide-react";

import { APP_PATHS, getAppBreadcrumbs, getNavItemsForRole, getRoleDisplayLabel, isAppRouteActive } from "@/app/route-metadata";
import { BrandLockup } from "@/components/brand/BrandLockup";
import { ContextualIntelligencePanel } from "@/components/platform/ContextualIntelligencePanel";
import { PlatformCommandPalette } from "@/components/platform/PlatformCommandPalette";
import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";
import { LegalFooter } from "@/components/trust/LegalFooter";
import { Badge } from "@/components/ui/badge";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useAuth } from "@/contexts/AuthContext";
import { useDashboardNotificationCenter, useOperationalAttentionQueue } from "@/features/layout/hooks";
import { NotificationsDropdown } from "@/features/layout/components/NotificationsDropdown";
import {
  PrinterOnboardingDialog,
  PrinterStatusDialog,
} from "@/features/layout/components/PrinterDialogs";
import { NOTIFICATION_FETCH_LIMIT, resolveNotificationTarget, resolveWorkspaceLabel, sidebarGroupOrder } from "@/features/layout/navigation-safety";
import { useManufacturerPrinterConnection } from "@/features/layout/useManufacturerPrinterConnection";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import { hasConsent } from "@/lib/consent";
import { cn } from "@/lib/utils";

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [contextOpen, setContextOpen] = useState(false);
  const reducedMotion = useReducedMotion();
  const { resolvedTheme, setTheme } = useTheme();

  const filteredNavItems = getNavItemsForRole(user?.role);
  const navGroups = sidebarGroupOrder
    .map((section) => ({
      section,
      items: filteredNavItems.filter((item) => item.section === section),
    }))
    .filter((group) => group.items.length > 0);
  const breadcrumbs = getAppBreadcrumbs(location.pathname, user?.role);
  const contextualHelpRoute = getContextualHelpRoute(location.pathname, user?.role);
  const notificationCenter = useDashboardNotificationCenter(user?.id, NOTIFICATION_FETCH_LIMIT);
  const attentionQueue = useOperationalAttentionQueue(Boolean(user?.id));
  const printerConnection = useManufacturerPrinterConnection({
    user,
    contextualHelpRoute,
    navigate,
    toast,
  });

  const handleLogout = () => {
    printerConnection.clearPrinterDialogSession();
    logout();
    navigate("/login");
  };

  const togglePlatformTheme = () => {
    if (!hasConsent("functional")) {
      toast({
        title: "Preference storage disabled",
        description: "Theme changes can be saved after functional cookies are enabled.",
      });
      return;
    }
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  };

  const workspaceLabel = resolveWorkspaceLabel(user);
  const currentPageLabel = breadcrumbs[breadcrumbs.length - 1]?.label || "Workspace";
  const roleLabel = getRoleDisplayLabel(user?.role);

  const contextPanel = (
    <ContextualIntelligencePanel
      pathname={location.pathname}
      role={user?.role}
      unreadCount={notificationCenter.unreadNotifications}
      notificationsLive={notificationCenter.notificationsLive}
      printer={{
        visible: printerConnection.isManufacturer,
        modeLabel: printerConnection.printerModeLabel,
        title: printerConnection.printerTitle,
        ready: printerConnection.effectivePrinterReady,
        degraded: printerConnection.printerDegraded,
        onOpen: printerConnection.openPrinterConnectionDialog,
      }}
      attentionQueue={attentionQueue.data || null}
      attentionQueueLoading={attentionQueue.isLoading || attentionQueue.isFetching}
    />
  );

  return (
    <div className="min-h-screen bg-mscqr-background text-mscqr-primary">
      <PlatformCommandPalette
        open={commandOpen}
        onOpenChange={setCommandOpen}
        role={user?.role}
        helpRoute={contextualHelpRoute}
      />

      <Sheet open={contextOpen} onOpenChange={setContextOpen}>
        <SheetContent side="right" className="w-[min(92vw,420px)] overflow-y-auto border-mscqr-border bg-mscqr-background-soft p-4">
          <SheetHeader className="sr-only">
            <SheetTitle>Workspace activity</SheetTitle>
            <SheetDescription>Recent MSCQR workspace updates and role-safe shortcuts.</SheetDescription>
          </SheetHeader>
          {contextPanel}
        </SheetContent>
      </Sheet>

      {sidebarOpen ? (
        <div
          className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <aside
        className={cn(
          "fixed left-0 top-0 z-50 h-full w-[19rem] transform border-r border-mscqr-border bg-mscqr-surface text-mscqr-primary shadow-2xl shadow-slate-950/10 transition-transform duration-200 ease-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-full flex-col">
          <div className="border-b border-mscqr-border bg-white px-5 py-5">
            <BrandLockup
              to={APP_PATHS.dashboard}
              className="gap-3"
              markClassName="size-11"
              iconClassName="h-7 w-7"
              textClassName="text-lg"
              ariaLabel="MSCQR workspace overview"
              onClick={() => setSidebarOpen(false)}
            />
          </div>

          <div className="border-b border-mscqr-border bg-white px-5 py-4">
            <p className="text-xs font-medium text-mscqr-muted">Workspace</p>
            <p className="mt-1 truncate text-sm font-semibold text-mscqr-primary">{workspaceLabel}</p>
            <p className="mt-1 text-xs text-mscqr-secondary">{roleLabel}</p>
          </div>

          <nav className="flex-1 overflow-y-auto px-3 py-5" aria-label="Authenticated MSCQR navigation">
            <div className="space-y-5">
              {navGroups.map((group) => (
                <div key={group.section}>
                  <p className="px-3 text-xs font-semibold text-mscqr-muted">{group.section}</p>
                  <div className="mt-2 space-y-1">
                    {group.items.map((item) => {
                      const isActive = isAppRouteActive(location.pathname, item.href);
                      return (
                        <Link
                          key={item.href}
                          to={item.href}
                          onClick={() => setSidebarOpen(false)}
                          className={cn(
                            "group relative flex items-center gap-3 rounded-2xl px-3 py-2.5 text-sm font-medium transition",
                            isActive
                              ? "text-mscqr-primary shadow-sm"
                              : "text-mscqr-secondary hover:bg-mscqr-surface-muted/70 hover:text-mscqr-primary",
                          )}
                        >
                          {isActive && !reducedMotion ? (
                            <motion.span
                              layoutId="platform-active-nav"
                              className="absolute inset-0 rounded-2xl border border-mscqr-accent/35 bg-mscqr-accent-soft/40"
                              transition={{ type: "spring", stiffness: 420, damping: 34 }}
                            />
                          ) : isActive ? (
                            <span className="absolute inset-0 rounded-2xl border border-mscqr-accent/35 bg-mscqr-accent-soft/40" />
                          ) : null}
                          <span
                            className={cn(
                              "relative flex size-9 items-center justify-center rounded-xl border transition",
                              isActive
                                ? "border-mscqr-accent/35 bg-mscqr-surface text-mscqr-accent"
                                : "border-transparent bg-mscqr-surface-muted/45 text-mscqr-muted group-hover:text-mscqr-accent",
                            )}
                          >
                            <item.icon className="size-4" />
                          </span>
                          <span className="relative truncate">{item.label}</span>
                          {group.section === "Advanced" ? (
                            <span className="relative ml-auto rounded-full bg-mscqr-surface-muted px-2 py-0.5 text-[11px] font-medium text-mscqr-muted">
                              Admin
                            </span>
                          ) : null}
                        </Link>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </nav>

          <div className="border-t border-mscqr-border p-4">
            <div className="rounded-2xl border border-mscqr-border bg-white p-3">
              <div className="flex items-center gap-3">
                <div className="flex size-10 items-center justify-center rounded-full bg-mscqr-accent-soft text-sm font-semibold text-mscqr-accent">
                  {user?.name?.charAt(0) || "U"}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{user?.name || "User"}</p>
                  <p className="truncate text-xs text-mscqr-secondary">{user?.email || getRoleDisplayLabel(user?.role)}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-[19rem]">
        {printerConnection.isManufacturer ? (
          <PrinterOnboardingDialog
            open={printerConnection.printerOnboardingOpen}
            onOpenChange={printerConnection.setPrinterOnboardingOpen}
            localPrinterAgent={printerConnection.localPrinterAgent}
            printerHasInventory={printerConnection.printerHasInventory}
            selectedPrinterName={printerConnection.selectedPrinterName}
            onInstallConnector={printerConnection.goToConnectorDownload}
            onCheckAgain={printerConnection.refreshPrinterConnectionStatus}
            onOpenHelp={printerConnection.goToHelp}
            onCloseForNow={printerConnection.dismissPrinterOnboarding}
          />
        ) : null}

        <header className="sticky top-0 z-30 border-b border-mscqr-border bg-white/90 px-3 py-3 backdrop-blur-xl lg:px-6">
          <div className="flex min-w-0 items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="rounded-xl border border-mscqr-border bg-mscqr-surface p-2 text-mscqr-primary hover:bg-mscqr-surface-muted lg:hidden"
              aria-label="Open sidebar"
            >
              <Menu className="h-5 w-5" />
            </button>

            <div className="hidden min-w-0 sm:block">
              <p className="truncate text-sm font-semibold text-mscqr-primary">
                {currentPageLabel}
              </p>
              <p className="truncate text-xs text-mscqr-secondary">
                {workspaceLabel} · {roleLabel}
              </p>
            </div>
          </div>

          <div className="ml-3 flex items-center gap-1 sm:gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setCommandOpen(true)}
              className="hidden min-w-[12rem] justify-between border-mscqr-border bg-mscqr-surface text-mscqr-secondary hover:bg-mscqr-surface-muted md:inline-flex"
              aria-label="Open command palette"
            >
              <span className="inline-flex items-center gap-2">
                <Command className="h-4 w-4" />
                Search workspace
              </span>
              <kbd className="rounded border border-mscqr-border bg-mscqr-surface-muted px-1.5 py-0.5 font-mono text-[10px] text-mscqr-muted">⌘K</kbd>
            </Button>

            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => setCommandOpen(true)}
              className="md:hidden"
              aria-label="Open command palette"
            >
              <Command className="h-4 w-4" />
            </Button>

            <NotificationsDropdown
              unreadNotifications={notificationCenter.unreadNotifications}
              visibleNotifications={notificationCenter.visibleNotifications}
              notificationsLoading={notificationCenter.notificationsLoading}
              notificationsLive={notificationCenter.notificationsLive}
              clearingNotificationIdSet={notificationCenter.clearingNotificationIdSet}
              clearingNotifications={notificationCenter.clearingNotifications}
              hasVisibleNotifications={notificationCenter.hasVisibleNotifications}
              notificationPanelCleared={notificationCenter.notificationPanelCleared}
              canClearNotifications={notificationCenter.canClearNotifications}
              onMarkAllNotificationsRead={notificationCenter.markAllNotificationsRead}
              onNotificationOpen={async (notification) => {
                await notificationCenter.markNotificationRead(notification.id);
                navigate(resolveNotificationTarget(notification));
              }}
              onClearNotifications={notificationCenter.clearNotifications}
            />

            {printerConnection.isManufacturer ? (
              <Button
                variant="outline"
                size="sm"
                onClick={printerConnection.openPrinterConnectionDialog}
                className={cn("mr-1 gap-2", printerConnection.printerToneClass)}
                title={printerConnection.printerTitle}
              >
                <Printer className="h-4 w-4" />
                <span className="hidden md:inline">{`Printing ${printerConnection.printerModeLabel}`}</span>
                <span className="md:hidden">{printerConnection.printerModeLabel}</span>
                {printerConnection.printerDegraded ? (
                  <Badge
                    variant="outline"
                    className="border-amber-300 bg-amber-100/80 text-[10px] font-semibold uppercase tracking-[0.14em] text-amber-800"
                  >
                    Recovery mode
                  </Badge>
                ) : null}
              </Button>
            ) : null}

            {printerConnection.isManufacturer &&
            !printerConnection.effectivePrinterReady &&
            printerConnection.managedNetworkPrinters.length === 0 ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={printerConnection.goToConnectorDownload}
                className="mr-1 hidden md:inline-flex"
              >
                Install printer helper
              </Button>
            ) : null}

            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={togglePlatformTheme}
              aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
              className="hidden sm:inline-flex"
            >
              {resolvedTheme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </Button>

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setContextOpen(true)}
              aria-label="Open workspace activity"
              className="gap-2"
            >
              <Activity className="h-4 w-4" />
              <span className="hidden lg:inline">Activity</span>
            </Button>

            <SupportIssueLauncher />

            <Button asChild variant="ghost" className="mr-1 gap-2">
              <Link to={contextualHelpRoute} data-testid="open-help">
                <CircleHelp className="h-4 w-4 text-muted-foreground" />
                <span className="hidden sm:inline">Help</span>
              </Link>
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                    <span className="text-sm font-semibold text-primary">{user?.name?.charAt(0) || "U"}</span>
                  </div>
                  <span className="hidden sm:inline">{user?.name || "User"}</span>
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                </Button>
              </DropdownMenuTrigger>

              <DropdownMenuContent align="end" className="w-56">
                <div className="px-3 py-2">
                  <p className="text-sm font-medium">{user?.name}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                </div>

                <DropdownMenuSeparator />

                <DropdownMenuItem onClick={() => navigate(APP_PATHS.settings)}>
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </DropdownMenuItem>

                <DropdownMenuSeparator />

                <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                  <LogOut className="mr-2 h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          </div>
        </header>

        {printerConnection.isManufacturer ? (
          <PrinterStatusDialog
            open={printerConnection.printerDialogOpen}
            onOpenChange={printerConnection.setPrinterDialogOpen}
            effectivePrinterDiagnostics={printerConnection.effectivePrinterDiagnostics}
            effectivePrinterReady={printerConnection.effectivePrinterReady}
            printerUnavailable={printerConnection.printerUnavailable}
            printerIdentity={printerConnection.printerIdentity}
            printerSummaryMessage={printerConnection.printerSummaryMessage}
            printerNextStep={printerConnection.printerNextStep}
            printerUpdatedLabel={printerConnection.printerUpdatedLabel}
            printerFeedLabel={printerConnection.printerFeedLabel}
            printerStatusLive={printerConnection.printerStatusLive}
            printerDegraded={printerConnection.printerDegraded}
            printerDegradedMessage={printerConnection.printerDegradedMessage}
            selectedPrinter={printerConnection.selectedPrinter}
            shouldUseManagedPrinterSummary={printerConnection.shouldUseManagedPrinterSummary}
            preferredManagedNetworkPrinter={printerConnection.preferredManagedNetworkPrinter}
            selectedPrinterName={printerConnection.selectedPrinterName}
            printerName={printerConnection.printerName}
            printerAgeSeconds={printerConnection.printerAgeSeconds}
            managedNetworkPrinters={printerConnection.managedNetworkPrinters}
            detectedPrinters={printerConnection.detectedPrinters}
            activePrinterId={printerConnection.activePrinterId}
            selectedLocalPrinterId={printerConnection.selectedLocalPrinterId}
            selectedPrinterIsActive={printerConnection.selectedPrinterIsActive}
            printerDiscoveryCountLabel={printerConnection.printerDiscoveryCountLabel}
            printerSwitching={printerConnection.printerSwitching}
            onSelectedLocalPrinterChange={printerConnection.setSelectedLocalPrinterId}
            onRefreshStatus={printerConnection.refreshPrinterConnectionStatus}
            onInstallConnector={printerConnection.goToConnectorDownload}
            onOpenPrinterSetup={printerConnection.goToPrinterSetup}
            onOpenBatches={printerConnection.goToBatches}
            onOpenHelp={printerConnection.goToHelp}
            onClose={() => printerConnection.setPrinterDialogOpen(false)}
            onSwitchLocalPrinter={(targetPrinterId) => {
              void printerConnection.switchLocalPrinter(targetPrinterId);
            }}
            workstationDeviceName={printerConnection.workstationDeviceName}
          />
        ) : null}

        <main className="relative p-3 lg:p-6">
          <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_18%_8%,hsl(var(--mscqr-accent)/0.08),transparent_30%)]" />
          <div className="grid items-start gap-6">
            <section className="min-w-0">
              {breadcrumbs.length > 0 ? (
                <div className="mb-4 rounded-2xl border border-mscqr-border bg-mscqr-surface/70 px-4 py-3">
                  <Breadcrumb>
                    <BreadcrumbList>
                      {breadcrumbs.map((crumb, index) => (
                        <React.Fragment key={`${crumb.label}-${index}`}>
                          {index > 0 ? <BreadcrumbSeparator /> : null}
                          <BreadcrumbItem>
                            <BreadcrumbPage className="text-mscqr-secondary">{crumb.label}</BreadcrumbPage>
                          </BreadcrumbItem>
                        </React.Fragment>
                      ))}
                    </BreadcrumbList>
                  </Breadcrumb>
                </div>
              ) : null}
              {children}
            </section>

          </div>
        </main>

        <footer className="px-3 pb-6 lg:px-6">
          <div className="space-y-4 rounded-[1.5rem] border border-mscqr-border bg-mscqr-surface/70 p-3">
            <div className="text-center text-xs text-muted-foreground">
              Need guidance on this page?{" "}
              <Link to={contextualHelpRoute} className="text-foreground underline-offset-4 hover:underline">
                Open the relevant help section
              </Link>
              .
            </div>
            <LegalFooter className="rounded-2xl border border-mscqr-border bg-mscqr-surface" />
          </div>
        </footer>
      </div>
    </div>
  );
}
