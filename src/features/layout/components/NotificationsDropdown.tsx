import { Bell, Inbox, Sparkles, Trash2 } from "lucide-react";

import { friendlyReferenceLabel, friendlyReferenceWords } from "@/lib/friendly-reference";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export type DashboardNotification = {
  id: string;
  type?: string | null;
  title?: string | null;
  body?: string | null;
  createdAt?: string | null;
  readAt?: string | null;
  data?: unknown;
  incidentId?: string | null;
};

type NotificationsDropdownProps = {
  unreadNotifications: number;
  visibleNotifications: DashboardNotification[];
  notificationsLoading: boolean;
  notificationsLive: boolean;
  clearingNotificationIdSet: Set<string>;
  clearingNotifications: boolean;
  hasVisibleNotifications: boolean;
  notificationPanelCleared: boolean;
  canClearNotifications: boolean;
  onMarkAllNotificationsRead: () => void | Promise<void>;
  onNotificationOpen: (notification: DashboardNotification) => void | Promise<void>;
  onClearNotifications: () => void | Promise<void>;
};

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
    {
      value: notification.incidentId,
      label: notification.incidentId ? friendlyReferenceLabel(String(notification.incidentId), "Case") : "Case",
    },
    {
      value: data.ticketReference,
      label: data.ticketReference ? friendlyReferenceLabel(String(data.ticketReference), "Ticket") : "Ticket",
    },
    {
      value: data.referenceCode,
      label: data.referenceCode ? friendlyReferenceLabel(String(data.referenceCode), "Ticket") : "Ticket",
    },
    { value: data.requestId, label: "Code request" },
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
      title: "Direct-print job prepared",
      body: `${batchName}${qty > 0 ? ` ready for secure direct-print (${qty} codes).` : " ready for secure direct-print."}`,
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

export function NotificationsDropdown({
  unreadNotifications,
  visibleNotifications,
  notificationsLoading,
  notificationsLive,
  clearingNotificationIdSet,
  clearingNotifications,
  hasVisibleNotifications,
  notificationPanelCleared,
  canClearNotifications,
  onMarkAllNotificationsRead,
  onNotificationOpen,
  onClearNotifications,
}: NotificationsDropdownProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="relative mr-1 overflow-visible rounded-full border-white/50 bg-white/65 shadow-[0_12px_22px_-18px_rgba(15,23,42,0.45)] dark:border-white/10 dark:bg-white/5"
          aria-label="Open notifications"
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
                  {visibleNotifications.length > 0 ? (
                    <span className="rounded-full border border-white/25 bg-white/35 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                      {visibleNotifications.length} total
                    </span>
                  ) : null}
                  {unreadNotifications > 0 ? (
                    <span className="rounded-full border border-emerald-300/35 bg-emerald-400/10 px-2 py-0.5 text-emerald-800 dark:text-emerald-200">
                      {unreadNotifications} unread
                    </span>
                  ) : null}
                </div>
              </div>

              <Button
                variant="outline"
                size="sm"
                className="h-8 rounded-full px-3 text-[11px]"
                disabled={notificationsLoading || unreadNotifications === 0}
                onClick={onMarkAllNotificationsRead}
              >
                <Sparkles className="h-3.5 w-3.5" />
                Mark all read
              </Button>
            </div>
          </div>

          <div className="relative p-3 pt-2">
            <div className="relative rounded-2xl border border-white/25 bg-white/38 p-2 shadow-[0_10px_24px_-20px_rgba(15,23,42,0.35)] dark:border-white/10 dark:bg-white/5">
              <div className="relative min-h-[18.5rem]">
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
                  <ScrollArea type="always" scrollHideDelay={0} className="h-[24rem] pr-1">
                    <div className="space-y-2 p-1 animate-in fade-in-0 slide-in-from-bottom-1 duration-200">
                      {visibleNotifications.map((item, index) => {
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
                                await onNotificationOpen(item);
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
                  </ScrollArea>
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

              <div className="mt-3 flex items-center justify-end border-t border-white/20 px-1 pt-3 dark:border-white/10">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-10 rounded-full border-white/45 bg-white/75 px-3.5 text-xs font-semibold shadow-[0_16px_24px_-16px_rgba(15,23,42,0.5)] dark:border-white/15 dark:bg-slate-900/70"
                  disabled={!canClearNotifications}
                  onClick={onClearNotifications}
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
  );
}
