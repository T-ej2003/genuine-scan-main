import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { friendlyReferenceLabel, friendlyReferenceWords } from "@/lib/friendly-reference";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { getContextualHelpRoute } from "@/help/contextual-help";
import apiClient from "@/lib/api-client";
import {
  LayoutDashboard,
  Building2,
  Factory,
  FileText,
  Settings,
  LogOut,
  Menu,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Shield,
  ScanEye,
  ShieldAlert,
  CircleHelp,
  Bell,
  Sparkles,
  SlidersHorizontal,
  Trash2,
  Inbox,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Slider } from "@/components/ui/slider";
import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  roles: string[];
}

type DashboardNotification = {
  id: string;
  type?: string | null;
  title?: string | null;
  body?: string | null;
  createdAt?: string | null;
  readAt?: string | null;
  data?: unknown;
  incidentId?: string | null;
};

const NOTIFICATION_FETCH_LIMIT = 24;
const NOTIFICATION_WINDOW_SIZE = 4;
const NOTIFICATION_CLEAR_ANIMATION_MS = 260;

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Licensees", href: "/licensees", icon: Building2, roles: ["super_admin"] },
  { label: "QR Requests", href: "/qr-requests", icon: FileText, roles: ["super_admin", "licensee_admin"] },
  { label: "Batches", href: "/batches", icon: FileText, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Manufacturers", href: "/manufacturers", icon: Factory, roles: ["super_admin", "licensee_admin"] },
  { label: "QR Tracking", href: "/qr-tracking", icon: ScanEye, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Support", href: "/support", icon: CircleHelp, roles: ["super_admin"] },
  { label: "IR Center", href: "/ir", icon: Shield, roles: ["super_admin"] },
  { label: "Incidents", href: "/incidents", icon: ShieldAlert, roles: ["super_admin"] },
  { label: "Governance", href: "/governance", icon: Shield, roles: ["super_admin"] },
  { label: "Audit Logs", href: "/audit-logs", icon: FileText, roles: ["super_admin", "licensee_admin"] },
];

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notifications, setNotifications] = useState<DashboardNotification[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsLive, setNotificationsLive] = useState(false);
  const [dismissedNotificationIds, setDismissedNotificationIds] = useState<string[]>([]);
  const [clearingNotificationIds, setClearingNotificationIds] = useState<string[]>([]);
  const [clearingNotifications, setClearingNotifications] = useState(false);
  const [notificationWindowStart, setNotificationWindowStart] = useState(0);
  const [notificationMotionSeed, setNotificationMotionSeed] = useState(0);
  const clearNotificationsTimerRef = useRef<number | null>(null);

  const filteredNavItems = navItems.filter((item) => user && item.roles.includes(user.role));
  const contextualHelpRoute = getContextualHelpRoute(location.pathname, user?.role);

  const applyNotificationSnapshot = (rows: DashboardNotification[], unread: number) => {
    setNotifications(rows);
    setUnreadNotifications(Number.isFinite(unread) ? unread : 0);

    const rowIds = new Set(rows.map((row) => String(row?.id || "")).filter(Boolean));
    setDismissedNotificationIds((prev) => prev.filter((id) => rowIds.has(id)));
  };

  const loadNotifications = async () => {
    if (!user) return;
    setNotificationsLoading(true);
    try {
      const response = await apiClient.getNotifications({ limit: NOTIFICATION_FETCH_LIMIT, offset: 0 });
      if (!response.success) {
        setNotifications([]);
        setUnreadNotifications(0);
        return;
      }
      const payload = (response.data && typeof response.data === "object" ? response.data : {}) as {
        notifications?: DashboardNotification[];
        unread?: number;
      };
      const rows = Array.isArray(payload.notifications) ? payload.notifications : [];
      applyNotificationSnapshot(rows, Number(payload.unread || 0));
    } catch {
      setNotifications([]);
      setUnreadNotifications(0);
    } finally {
      setNotificationsLoading(false);
    }
  };

  useEffect(() => {
    loadNotifications();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => {
    if (!user) return;
    const timer = window.setInterval(() => {
      loadNotifications();
    }, 90_000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => {
    if (!user) return;
    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
      clearNotificationsTimerRef.current = null;
    }

    const stop = apiClient.streamNotifications(
      (payload) => {
        const rows = Array.isArray(payload.notifications) ? payload.notifications : [];
        applyNotificationSnapshot(rows, Number(payload.unread || 0));
      },
      () => {
        setNotificationsLive(false);
      },
      () => {
        setNotificationsLive(true);
      },
      { limit: NOTIFICATION_FETCH_LIMIT }
    );

    return () => {
      setNotificationsLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const markNotificationRead = async (id: string) => {
    if (!id) return;
    await apiClient.markNotificationRead(id);
    await loadNotifications();
  };

  const notificationTarget = (notification: DashboardNotification) => {
    const data = (notification?.data && typeof notification.data === "object" ? notification.data : {}) as Record<string, unknown>;
    if (typeof data.targetRoute === "string" && data.targetRoute.trim()) return data.targetRoute.trim();
    if (data.ticketId) return `/support?ticketId=${encodeURIComponent(String(data.ticketId))}`;
    if (data.ticketReference) return `/support?reference=${encodeURIComponent(String(data.ticketReference))}`;
    if (notification?.incidentId) return `/incidents?incidentId=${encodeURIComponent(String(notification.incidentId))}`;
    return "/dashboard";
  };

  const dismissedNotificationIdSet = useMemo(() => new Set(dismissedNotificationIds), [dismissedNotificationIds]);
  const clearingNotificationIdSet = useMemo(() => new Set(clearingNotificationIds), [clearingNotificationIds]);

  const visibleNotifications = useMemo(
    () => notifications.filter((item) => item?.id && !dismissedNotificationIdSet.has(String(item.id))),
    [notifications, dismissedNotificationIdSet]
  );

  const notificationTimelineMax = Math.max(0, visibleNotifications.length - NOTIFICATION_WINDOW_SIZE);

  useEffect(() => {
    setNotificationWindowStart((prev) => Math.min(prev, notificationTimelineMax));
  }, [notificationTimelineMax]);

  useEffect(() => {
    setNotificationMotionSeed((prev) => prev + 1);
  }, [notificationWindowStart, visibleNotifications.length]);

  useEffect(() => {
    return () => {
      if (clearNotificationsTimerRef.current) {
        window.clearTimeout(clearNotificationsTimerRef.current);
      }
    };
  }, []);

  const notificationItems = useMemo(
    () => visibleNotifications.slice(notificationWindowStart, notificationWindowStart + NOTIFICATION_WINDOW_SIZE),
    [visibleNotifications, notificationWindowStart]
  );

  const handleMarkAllNotificationsRead = async () => {
    if (notifications.length === 0 && unreadNotifications === 0) return;

    const readAt = new Date().toISOString();
    setNotifications((prev) => prev.map((item) => ({ ...item, readAt: item.readAt || readAt })));
    setUnreadNotifications(0);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      await loadNotifications();
    }
  };

  const handleClearNotifications = async () => {
    if (notificationsLoading || clearingNotifications || visibleNotifications.length === 0) return;

    const idsToClear = visibleNotifications.map((item) => String(item.id)).filter(Boolean);
    if (idsToClear.length === 0) return;

    const unreadBeingCleared = visibleNotifications.reduce((count, item) => count + (!item.readAt ? 1 : 0), 0);
    const readAt = new Date().toISOString();

    setClearingNotifications(true);
    setClearingNotificationIds(idsToClear);
    setNotifications((prev) =>
      prev.map((item) => (idsToClear.includes(String(item.id)) ? { ...item, readAt: item.readAt || readAt } : item))
    );
    setUnreadNotifications((prev) => Math.max(0, prev - unreadBeingCleared));

    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
    }

    clearNotificationsTimerRef.current = window.setTimeout(() => {
      setDismissedNotificationIds((prev) => Array.from(new Set([...prev, ...idsToClear])).slice(-300));
      setClearingNotificationIds([]);
      setClearingNotifications(false);
      clearNotificationsTimerRef.current = null;
    }, NOTIFICATION_CLEAR_ANIMATION_MS);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      // Local clear is non-destructive UI state; keep it smooth even if network sync fails.
    }
  };

  const stepNotificationTimeline = (direction: "newer" | "older") => {
    setNotificationWindowStart((prev) => {
      if (direction === "newer") return Math.max(0, prev - 1);
      return Math.min(notificationTimelineMax, prev + 1);
    });
  };

  const canMoveTimelineToNewer = notificationWindowStart > 0;
  const canMoveTimelineToOlder = notificationWindowStart < notificationTimelineMax;
  const hasVisibleNotifications = visibleNotifications.length > 0;
  const notificationPanelCleared = notifications.length > 0 && visibleNotifications.length === 0;
  const canClearNotifications = hasVisibleNotifications && !notificationsLoading && !clearingNotifications;
  const timelineVisibleStart = hasVisibleNotifications ? notificationWindowStart + 1 : 0;
  const timelineVisibleEnd = hasVisibleNotifications ? notificationWindowStart + notificationItems.length : 0;

  const formatNotificationDate = (value?: string | null) => {
    if (!value) return "Time unavailable";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Time unavailable";
    return date.toLocaleString();
  };

  const isNotificationUnread = (notification: DashboardNotification) => !notification.readAt;

  const notificationToneClasses = (notification: DashboardNotification) => {
    const text = `${notification.title || ""} ${notification.body || ""}`.toLowerCase();
    if (text.includes("incident")) {
      return {
        accent: "bg-amber-400/90",
        border: "border-amber-300/35",
        glow: "shadow-[0_0_0_1px_rgba(251,191,36,0.12)_inset]",
        chip: "bg-amber-400/15 text-amber-900 dark:text-amber-200 border-amber-300/30",
      };
    }
    if (text.includes("request")) {
      return {
        accent: "bg-sky-400/90",
        border: "border-sky-300/35",
        glow: "shadow-[0_0_0_1px_rgba(56,189,248,0.12)_inset]",
        chip: "bg-sky-400/15 text-sky-900 dark:text-sky-200 border-sky-300/30",
      };
    }
    return {
      accent: "bg-emerald-400/90",
      border: "border-emerald-300/35",
      glow: "shadow-[0_0_0_1px_rgba(16,185,129,0.12)_inset]",
      chip: "bg-emerald-400/15 text-emerald-900 dark:text-emerald-200 border-emerald-300/30",
    };
  };

  const toHumanWords = (value?: string | null) =>
    String(value || "")
      .trim()
      .replace(/_/g, " ")
      .replace(/\s+/g, " ")
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());

  const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const replaceOpaqueRefs = (text: string, notification: DashboardNotification) => {
    const raw = String(text || "");
    if (!raw) return raw;

    const data =
      notification?.data && typeof notification.data === "object"
        ? (notification.data as Record<string, unknown>)
        : ({} as Record<string, unknown>);

    let out = raw;

    const exactReplacements: Array<{ value?: unknown; label: string }> = [
      { value: notification.incidentId, label: notification.incidentId ? friendlyReferenceLabel(String(notification.incidentId), "Case") : "Case" },
      { value: data.ticketReference, label: data.ticketReference ? friendlyReferenceLabel(String(data.ticketReference), "Ticket") : "Ticket" },
      { value: data.referenceCode, label: data.referenceCode ? friendlyReferenceLabel(String(data.referenceCode), "Ticket") : "Ticket" },
      { value: data.requestId, label: "QR request" },
      { value: data.batchId, label: "Batch" },
      { value: data.printJobId, label: "Print job" },
    ];

    for (const entry of exactReplacements) {
      const value = String(entry.value || "").trim();
      if (!value) continue;
      out = out.replace(new RegExp(escapeRegExp(value), "g"), entry.label);
    }

    out = out.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, (m) =>
      friendlyReferenceLabel(m, "Case")
    );

    out = out.replace(/\b[0-9a-f]{8}\b/gi, (m) => `Ref ${friendlyReferenceWords(m, 2)}`);

    out = out.replace(/\bAUTH_[A-Z0-9_]+\b/g, (m) => toHumanWords(m));
    return out;
  };

  const notificationCopy = (notification: DashboardNotification) => {
    const data =
      notification?.data && typeof notification.data === "object"
        ? (notification.data as Record<string, unknown>)
        : ({} as Record<string, unknown>);
    const type = String(notification.type || "").trim();

    if (type === "manufacturer_batch_assigned") {
      const batchName = String(data.batchName || "assigned batch").trim();
      const qty = Number(data.quantity || 0);
      return {
        title: "New batch assigned",
        body: `${batchName}${qty > 0 ? ` is ready for printing (${qty} codes).` : " is ready for printing."}`,
      };
    }
    if (type === "manufacturer_print_job_created") {
      const batchName = String(data.batchName || "batch").trim();
      const qty = Number(data.quantity || 0);
      return {
        title: "Print job prepared",
        body: `${batchName}${qty > 0 ? ` print package prepared for ${qty} codes.` : " print package is ready."}`,
      };
    }
    if (type === "manufacturer_print_job_confirmed") {
      const batchName = String(data.batchName || "batch").trim();
      const qty = Number(data.printedCodes || 0);
      return {
        title: "Printing confirmed",
        body: `${batchName}${qty > 0 ? ` confirmed with ${qty} printed codes.` : " printing was confirmed."}`,
      };
    }

    const fallbackTitle = notification.title?.trim() || (type ? toHumanWords(type) : "Notification");
    const fallbackBody = notification.body?.trim() || "Open to view details.";
    return {
      title: replaceOpaqueRefs(fallbackTitle, notification),
      body: replaceOpaqueRefs(fallbackBody, notification),
    };
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const getRoleLabel = (role?: string) => {
    if (!role) return "User";
    switch (role) {
      case "super_admin":
        return "Super Admin";
      case "licensee_admin":
        return "Licensee Admin";
      case "manufacturer":
        return "Manufacturer";
      default:
        return role;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 z-50 h-full w-64 bg-sidebar text-sidebar-foreground transform transition-transform duration-200 ease-in-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center gap-2 px-6 border-b border-sidebar-border">
            <img src="/brand/authenticqr-mark.svg" alt="MSCQR logo" className="h-8 w-8" />
            <span className="font-bold text-lg">MSCQR</span>
          </div>

          <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
            {filteredNavItems.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors",
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
              <div className="h-10 w-10 rounded-full bg-sidebar-accent flex items-center justify-center">
                <span className="text-sm font-semibold text-sidebar-accent-foreground">
                  {user?.name?.charAt(0) || "U"}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || "User"}</p>
                <p className="text-xs text-sidebar-foreground/60 truncate">{getRoleLabel(user?.role)}</p>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 h-16 bg-card border-b border-border flex items-center justify-between px-4 lg:px-6">
          <button
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden p-2 rounded-md hover:bg-muted"
            aria-label="Open sidebar"
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex-1" />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative mr-1 overflow-visible rounded-full border-white/50 bg-white/65 shadow-[0_12px_22px_-18px_rgba(15,23,42,0.45)] dark:border-white/10 dark:bg-white/5"
              >
                <Bell className="h-4 w-4 text-muted-foreground" />
                {unreadNotifications > 0 ? (
                  <span className="pointer-events-none absolute -right-1.5 -top-1.5 z-20 inline-flex min-h-5 min-w-5 items-center justify-center rounded-full border-2 border-card bg-emerald-500 px-1.5 text-[10px] font-bold leading-none text-white shadow-[0_14px_20px_-14px_rgba(16,185,129,0.95),0_0_0_1px_rgba(16,185,129,0.25)] ring-1 ring-emerald-300/30 dark:border-slate-900">
                    {unreadNotifications > 9 ? "9+" : unreadNotifications}
                  </span>
                ) : null}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              sideOffset={10}
              className="w-[92vw] max-w-[27rem] rounded-2xl border border-white/35 bg-white/78 p-0 text-foreground shadow-[0_26px_60px_-28px_rgba(2,6,23,0.48),0_18px_28px_-22px_rgba(15,23,42,0.35)] backdrop-blur-2xl dark:border-white/10 dark:bg-slate-950/78"
            >
              <div className="relative overflow-hidden rounded-2xl">
                <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-[linear-gradient(180deg,rgba(16,185,129,0.12),rgba(59,130,246,0.04),transparent)]" />

                <div className="relative border-b border-white/25 px-4 py-3 dark:border-white/10">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-base font-semibold tracking-tight">Notifications</p>
                        <span className="inline-flex h-6 items-center rounded-full border border-white/40 bg-white/45 px-2 text-[11px] font-medium text-foreground/80 dark:border-white/10 dark:bg-white/5 dark:text-foreground/70">
                          {visibleNotifications.length}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-white/35 bg-white/45 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                          <span
                            className={cn(
                              "inline-block h-2 w-2 rounded-full transition-colors",
                              notificationsLive ? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.12)]" : "bg-slate-300"
                            )}
                          />
                          {notificationsLive ? "Live feed active" : "Polling mode"}
                        </span>
                        {hasVisibleNotifications ? (
                          <span className="rounded-full border border-white/25 bg-white/35 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                            Showing {timelineVisibleStart}-{timelineVisibleEnd} of {visibleNotifications.length}
                          </span>
                        ) : null}
                      </div>
                    </div>

                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8 rounded-full px-3 text-[11px]"
                      disabled={notificationsLoading || unreadNotifications === 0}
                      onClick={handleMarkAllNotificationsRead}
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      Mark all read
                    </Button>
                  </div>

                  <div className="mt-3 rounded-xl border border-white/25 bg-white/40 p-3 dark:border-white/10 dark:bg-white/5">
                    <div className="mb-2 flex items-center justify-between text-[11px] font-medium text-muted-foreground">
                      <div className="inline-flex items-center gap-1.5">
                        <SlidersHorizontal className="h-3.5 w-3.5" />
                        Recent
                      </div>
                      <span className="text-foreground/80 dark:text-foreground/70">
                        {hasVisibleNotifications ? `${timelineVisibleStart}-${timelineVisibleEnd}` : "0"}
                      </span>
                      <span>Older</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 rounded-full"
                        disabled={!canMoveTimelineToNewer || notificationsLoading || clearingNotifications}
                        onClick={() => stepNotificationTimeline("newer")}
                        aria-label="Move toward most recent notifications"
                      >
                        <ChevronLeft className="h-3.5 w-3.5" />
                      </Button>
                      <Slider
                        value={[notificationWindowStart]}
                        min={0}
                        max={Math.max(notificationTimelineMax, 1)}
                        step={1}
                        disabled={notificationTimelineMax === 0 || notificationsLoading || clearingNotifications}
                        onValueChange={(value) => {
                          const next = Math.max(0, Math.min(notificationTimelineMax, Number(value?.[0] ?? 0)));
                          setNotificationWindowStart(next);
                        }}
                        className="flex-1"
                        aria-label="Notification timeline from recent to older"
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 rounded-full"
                        disabled={!canMoveTimelineToOlder || notificationsLoading || clearingNotifications}
                        onClick={() => stepNotificationTimeline("older")}
                        aria-label="Move toward older notifications"
                      >
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="relative p-3 pt-2">
                  <div className="relative rounded-2xl border border-white/25 bg-white/38 p-2 shadow-[0_10px_24px_-20px_rgba(15,23,42,0.35)] dark:border-white/10 dark:bg-white/5">
                    <div className="pointer-events-none absolute inset-x-4 top-0 h-10 bg-gradient-to-b from-white/35 to-transparent dark:from-white/5" />

                    <div className="relative min-h-[18.5rem] pb-16">
                      {notificationsLoading ? (
                        <div className="space-y-2 p-1">
                          {Array.from({ length: 4 }).map((_, index) => (
                            <div
                              key={`notification-skeleton-${index}`}
                              className="rounded-xl border border-white/20 bg-white/55 p-3 dark:border-white/10 dark:bg-white/5"
                            >
                              <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200/80 dark:bg-slate-700/70" />
                              <div className="mt-2 h-3 w-full animate-pulse rounded bg-slate-200/70 dark:bg-slate-700/60" />
                              <div className="mt-1 h-3 w-5/6 animate-pulse rounded bg-slate-200/60 dark:bg-slate-700/50" />
                              <div className="mt-2 h-3 w-1/3 animate-pulse rounded bg-slate-200/60 dark:bg-slate-700/50" />
                            </div>
                          ))}
                        </div>
                      ) : hasVisibleNotifications ? (
                        <div
                          key={`${notificationMotionSeed}-${notificationWindowStart}-${visibleNotifications.length}`}
                          className="space-y-2 p-1 animate-in fade-in-0 slide-in-from-bottom-1 duration-200"
                        >
                          {notificationItems.map((item, index) => {
                            const isUnread = isNotificationUnread(item);
                            const itemId = String(item.id);
                            const isClearingItem = clearingNotificationIdSet.has(itemId);
                            const tone = notificationToneClasses(item);
                            const copy = notificationCopy(item);

                            return (
                              <div
                                key={itemId}
                                className={cn(
                                  "overflow-hidden transition-[max-height,opacity,transform,margin] duration-300 ease-out",
                                  isClearingItem ? "max-h-0 opacity-0 -translate-y-2" : "max-h-56 opacity-100 translate-y-0"
                                )}
                                style={{ transitionDelay: isClearingItem ? `${index * 24}ms` : undefined }}
                              >
                                <DropdownMenuItem
                                  disabled={isClearingItem || clearingNotifications}
                                  onClick={async () => {
                                    await markNotificationRead(item.id);
                                    navigate(notificationTarget(item));
                                  }}
                                  className={cn(
                                    "group relative flex cursor-pointer flex-col items-start gap-1.5 rounded-xl border px-3 py-3 pr-10 transition-all duration-200 ease-out focus-visible:ring-1 focus-visible:ring-emerald-300/60",
                                    tone.border,
                                    tone.glow,
                                    isUnread
                                      ? "bg-white/80 hover:bg-white/95 dark:bg-slate-900/70 dark:hover:bg-slate-900/90"
                                      : "bg-white/55 hover:bg-white/75 dark:bg-slate-900/45 dark:hover:bg-slate-900/70"
                                  )}
                                >
                                  <span
                                    className={cn(
                                      "absolute inset-y-2 left-0 w-1 rounded-r-full transition-opacity",
                                      tone.accent,
                                      isUnread ? "opacity-100" : "opacity-35"
                                    )}
                                  />
                                  <div className="flex w-full items-start justify-between gap-2 pl-2">
                                    <p className={cn("line-clamp-1 text-sm font-semibold tracking-tight", isUnread ? "text-foreground" : "text-foreground/90")}>
                                      {copy.title}
                                    </p>
                                    <span
                                      className={cn(
                                        "inline-flex h-5 shrink-0 items-center rounded-full border px-1.5 text-[10px] font-semibold uppercase tracking-wide",
                                        isUnread
                                          ? tone.chip
                                          : "border-white/30 bg-white/40 text-muted-foreground dark:border-white/10 dark:bg-white/5"
                                      )}
                                    >
                                      {isUnread ? "New" : "Read"}
                                    </span>
                                  </div>

                                  <p className="line-clamp-2 pl-2 text-xs leading-5 text-muted-foreground">{copy.body}</p>
                                  <p className="pl-2 text-[11px] font-medium text-muted-foreground/90">{formatNotificationDate(item.createdAt)}</p>
                                </DropdownMenuItem>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <div className="flex min-h-[18.5rem] items-center justify-center p-3 animate-in fade-in-0 slide-in-from-bottom-1 duration-200">
                          <div className="w-full rounded-2xl border border-dashed border-white/30 bg-white/50 px-4 py-8 text-center dark:border-white/10 dark:bg-white/5">
                            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/40 bg-white/70 text-emerald-600 shadow-[0_10px_24px_-18px_rgba(16,185,129,0.55)] dark:border-white/10 dark:bg-white/5 dark:text-emerald-300">
                              <Inbox className="h-5 w-5" />
                            </div>
                            <p className="text-sm font-semibold tracking-tight">
                              {notificationPanelCleared ? "Notifications cleared" : "No notifications right now"}
                            </p>
                            <p className="mt-1 text-xs leading-5 text-muted-foreground">
                              {notificationPanelCleared
                                ? "New alerts will appear here automatically as activity happens."
                                : "Your latest alerts, policy events, and incident updates will appear here."}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="pointer-events-none absolute inset-x-0 bottom-0 h-20 rounded-b-2xl bg-gradient-to-t from-white/75 via-white/40 to-transparent dark:from-slate-950/70 dark:via-slate-950/30" />

                    <div className="absolute bottom-3 right-3 flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-10 rounded-full border-white/45 bg-white/75 px-3.5 text-xs font-semibold shadow-[0_16px_24px_-16px_rgba(15,23,42,0.5)] dark:border-white/15 dark:bg-slate-900/70"
                        disabled={!canClearNotifications}
                        onClick={handleClearNotifications}
                        aria-label="Clear notifications from the panel"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        {clearingNotifications ? "Clearing..." : "Clear notifications"}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>

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
                <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                  <span className="text-sm font-semibold text-primary">
                    {user?.name?.charAt(0) || "U"}
                  </span>
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

        <main className="p-4 lg:p-6">{children}</main>
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
