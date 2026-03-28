import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ChevronDown, CircleHelp, LogOut, Menu, Printer, Settings } from "lucide-react";

import { APP_PATHS, getAppBreadcrumbs, getNavItemsForRole, getRoleDisplayLabel, isAppRouteActive } from "@/app/route-metadata";
import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";
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
import { useAuth } from "@/contexts/AuthContext";
import { useDashboardNotificationCenter } from "@/features/layout/hooks";
import { NotificationsDropdown, type DashboardNotification } from "@/features/layout/components/NotificationsDropdown";
import {
  PrinterOnboardingDialog,
  PrinterStatusDialog,
} from "@/features/layout/components/PrinterDialogs";
import { useManufacturerPrinterConnection } from "@/features/layout/useManufacturerPrinterConnection";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const NOTIFICATION_FETCH_LIMIT = 24;

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const filteredNavItems = getNavItemsForRole(user?.role);
  const breadcrumbs = getAppBreadcrumbs(location.pathname, user?.role);
  const contextualHelpRoute = getContextualHelpRoute(location.pathname, user?.role);
  const notificationCenter = useDashboardNotificationCenter(user?.id, NOTIFICATION_FETCH_LIMIT);
  const printerConnection = useManufacturerPrinterConnection({
    user,
    contextualHelpRoute,
    navigate,
    toast,
  });

  const notificationTarget = (notification: DashboardNotification) => {
    const data =
      notification?.data && typeof notification.data === "object"
        ? (notification.data as Record<string, unknown>)
        : {};

    if (typeof data.targetRoute === "string" && data.targetRoute.trim()) return data.targetRoute.trim();
    if (data.ticketId) return `${APP_PATHS.support}?ticketId=${encodeURIComponent(String(data.ticketId))}`;
    if (data.ticketReference) return `${APP_PATHS.support}?reference=${encodeURIComponent(String(data.ticketReference))}`;
    if (notification?.incidentId) {
      return `${APP_PATHS.incidentResponse}?incidentId=${encodeURIComponent(String(notification.incidentId))}`;
    }
    return APP_PATHS.dashboard;
  };

  const handleLogout = () => {
    printerConnection.clearPrinterDialogSession();
    logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-background">
      {sidebarOpen ? (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <aside
        className={cn(
          "fixed left-0 top-0 z-50 h-full w-64 transform bg-sidebar text-sidebar-foreground transition-transform duration-200 ease-in-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center gap-2 border-b border-sidebar-border px-6">
            <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-8 w-8" />
            <span className="text-lg font-bold">MSCQR</span>
          </div>

          <nav className="flex-1 space-y-1 overflow-y-auto px-4 py-6">
            {filteredNavItems.map((item) => {
              const isActive = isAppRouteActive(location.pathname, item.href);
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    "flex items-center gap-3 rounded-lg px-4 py-3 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  )}
                >
                  <item.icon className="h-5 w-5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="border-t border-sidebar-border p-4">
            <div className="flex items-center gap-3 px-2 py-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-sidebar-accent">
                <span className="text-sm font-semibold text-sidebar-accent-foreground">
                  {user?.name?.charAt(0) || "U"}
                </span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{user?.name || "User"}</p>
                <p className="truncate text-xs text-sidebar-foreground/60">{getRoleDisplayLabel(user?.role)}</p>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-64">
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

        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-card px-4 lg:px-6">
          <button
            onClick={() => setSidebarOpen(true)}
            className="rounded-md p-2 hover:bg-muted lg:hidden"
            aria-label="Open sidebar"
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex-1" />

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
              navigate(notificationTarget(notification));
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
              <span className="hidden md:inline">{`Printer ${printerConnection.printerModeLabel}`}</span>
              <span className="md:hidden">{printerConnection.printerModeLabel}</span>
              {printerConnection.printerDegraded ? (
                <Badge
                  variant="outline"
                  className="border-amber-300 bg-amber-100/80 text-[10px] font-semibold uppercase tracking-[0.14em] text-amber-800"
                >
                  Degraded
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
              Install Connector
            </Button>
          ) : null}

          <SupportIssueLauncher />

          <Button asChild variant="ghost" className="mr-1 gap-2">
            <Link to={contextualHelpRoute}>
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

              <DropdownMenuItem onClick={() => navigate("/account")}>
                <Settings className="mr-2 h-4 w-4" />
                Account
              </DropdownMenuItem>

              <DropdownMenuSeparator />

              <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
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
            onOpenBatches={printerConnection.goToBatches}
            onOpenHelp={printerConnection.goToHelp}
            onClose={() => printerConnection.setPrinterDialogOpen(false)}
            onSwitchLocalPrinter={(targetPrinterId) => {
              void printerConnection.switchLocalPrinter(targetPrinterId);
            }}
            workstationDeviceName={printerConnection.workstationDeviceName}
          />
        ) : null}

        <main className="p-4 lg:p-6">
          {breadcrumbs.length > 0 ? (
            <div className="mb-4">
              <Breadcrumb>
                <BreadcrumbList>
                  {breadcrumbs.map((crumb, index) => (
                    <React.Fragment key={`${crumb.label}-${index}`}>
                      {index > 0 ? <BreadcrumbSeparator /> : null}
                      <BreadcrumbItem>
                        <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
                      </BreadcrumbItem>
                    </React.Fragment>
                  ))}
                </BreadcrumbList>
              </Breadcrumb>
            </div>
          ) : null}
          {children}
        </main>

        <footer className="px-4 pb-6 lg:px-6">
          <div className="text-center text-xs text-muted-foreground">
            Need guidance on this page?{" "}
            <Link to={contextualHelpRoute} className="text-foreground underline-offset-4 hover:underline">
              Open the relevant help section
            </Link>
            .
          </div>
        </footer>
      </div>
    </div>
  );
}
