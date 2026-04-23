import React, { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { getAppRouteLabel } from "@/app/route-metadata";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useToast } from "@/hooks/use-toast";
import { HELP_ASSISTANT_OPEN_EVENT, type HelpAssistantOpenPayload } from "@/help/assistant-events";
import { type HelpKbRole } from "@/help/kb";
import {
  getEntryById,
  getFallbackSuggestions,
  getShortAnswer,
  searchHelpEntries,
  type HelpSearchResult,
} from "@/help/kb-search";
import { useAuth } from "@/contexts/AuthContext";
import {
  CircleHelp,
  ChevronDown,
  ChevronUp,
  Flag,
  MessageCircleQuestion,
  MoveRight,
  SearchX,
  Send,
} from "lucide-react";

type AssistantTurn =
  | { id: string; kind: "intro"; text: string }
  | { id: string; kind: "user"; text: string }
  | { id: string; kind: "results"; query: string; results: HelpSearchResult[] }
  | { id: string; kind: "no_match"; query: string; suggestions: ReturnType<typeof getFallbackSuggestions> };

const mkTurnId = () => `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;

const routeLabel = (route: string) => {
  const appLabel = getAppRouteLabel(route);
  if (appLabel) return appLabel;

  const labels: Record<string, string> = {
    "/help": "Help hub",
    "/help/getting-access": "Getting access",
    "/help/setting-password": "Setting password",
    "/help/roles-permissions": "Roles & permissions",
    "/help/super-admin": "Super Admin docs",
    "/help/licensee-admin": "Licensee/Admin docs",
    "/help/manufacturer": "Manufacturer docs",
    "/help/customer": "Customer docs",
    "/help/incident-response": "Incident Response docs",
    "/help/policy-alerts": "Policy alerts docs",
    "/help/incident-actions": "Incident actions docs",
    "/help/communications": "Communications docs",
    "/verify": "Verify page",
    "/code-requests": "Code Requests",
    "/batches": "Batches",
    "/manufacturers": "Manufacturers",
    "/scan-activity": "Scan Activity",
    "/incidents": "Incident Response",
    "/support": "Support tickets",
    "/governance": "Governance",
    "/incident-response": "Incident Response",
    "/printer-diagnostics": "Printer Setup",
    "/printer-setup": "Printer Setup",
    "/settings": "Settings",
    "/account": "Account settings",
    "/login": "Sign in",
    "/accept-invite": "Accept invite",
    "/connector-download": "Install Connector",
    "/forgot-password": "Forgot password",
    "/reset-password": "Reset password",
  };
  if (labels[route]) return labels[route];
  const segment = route.split("/").filter(Boolean).pop() || route;
  return segment.replace(/[-_]/g, " ");
};

const ROLE_LABELS: Record<HelpKbRole, string> = {
  all: "All Roles",
  super_admin: "Super Admin",
  licensee: "Licensee/Admin",
  manufacturer: "Manufacturer",
  customer: "Customer",
};

const getActiveHelpRole = (pathname: string, role?: string): HelpKbRole => {
  if (role === "super_admin") return "all";
  if (pathname.startsWith("/verify") || pathname.startsWith("/scan")) return "customer";
  if (role === "licensee_admin") return "licensee";
  if (role === "manufacturer") return "manufacturer";
  return "customer";
};

const canUseEntryForRole = (entryRole: HelpKbRole, activeRole: HelpKbRole) => {
  if (activeRole === "all") return true;
  if (entryRole === "all") return true;
  return entryRole === activeRole;
};

const roleScopedIntro = (activeRole: HelpKbRole) => {
  if (activeRole === "all") {
    return "Super Admin mode: ask about any role workflow, policy, incident response, or customer verification.";
  }
  if (activeRole === "licensee") {
    return "Licensee/Admin mode: ask about inventory requests, the batch workspace, manufacturers, tracking, and account access.";
  }
  if (activeRole === "manufacturer") {
    return "Manufacturer mode: ask about assigned batches, printer setup, workstation printing, saved factory printers, shared printers, and status updates.";
  }
  return "Customer mode: ask about verification results, repeat scans, ownership claim, and counterfeit reporting.";
};

export default function HelpAssistantWidget() {
  const { user } = useAuth();
  const { toast } = useToast();
  const location = useLocation();
  const navigate = useNavigate();
  const endRef = useRef<HTMLDivElement | null>(null);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [isMobile, setIsMobile] = useState(false);
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});
  const [turns, setTurns] = useState<AssistantTurn[]>([]);

  const activeRole = useMemo(
    () => getActiveHelpRole(location.pathname, user?.role),
    [location.pathname, user?.role]
  );

  useEffect(() => {
    setTurns([
      {
        id: mkTurnId(),
        kind: "intro",
        text: roleScopedIntro(activeRole),
      },
    ]);
    setExpandedCards({});
  }, [activeRole]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 640px)");
    const sync = () => setIsMobile(media.matches);
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (!open) return;
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [turns, open]);

  useEffect(() => {
    const handleOpenEvent = (event: Event) => {
      const detail = (event as CustomEvent<HelpAssistantOpenPayload>).detail || {};
      setOpen(true);

      if (detail.entryId) {
        const entry = getEntryById(detail.entryId);
        if (!entry) return;
        if (!canUseEntryForRole(entry.role, activeRole)) {
          toast({
            title: "Role-scoped help",
            description: "This topic is outside your current support scope.",
          });
          return;
        }

        setTurns((prev) => [
          ...prev,
          {
            id: mkTurnId(),
            kind: "results",
            query: detail.query || entry.title,
            results: [
              {
                entry,
                score: 999,
                shortAnswer: getShortAnswer(entry.answer),
              },
            ],
          },
        ]);
        return;
      }

      if (detail.query) {
        runSearch(detail.query, { addUserTurn: true });
      }
    };

    window.addEventListener(HELP_ASSISTANT_OPEN_EVENT, handleOpenEvent as EventListener);
    return () => {
      window.removeEventListener(HELP_ASSISTANT_OPEN_EVENT, handleOpenEvent as EventListener);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeRole]);

  const runSearch = (rawQuery: string, options?: { addUserTurn?: boolean }) => {
    const trimmed = rawQuery.trim();
    if (!trimmed) return;

    const addUserTurn = options?.addUserTurn ?? true;
    const hits = searchHelpEntries(trimmed, activeRole, 3);

    setTurns((prev) => {
      const next = [...prev];
      if (addUserTurn) {
        next.push({ id: mkTurnId(), kind: "user", text: trimmed });
      }
      if (hits.length > 0) {
        next.push({ id: mkTurnId(), kind: "results", query: trimmed, results: hits });
      } else {
        next.push({
          id: mkTurnId(),
          kind: "no_match",
          query: trimmed,
          suggestions: getFallbackSuggestions(activeRole, 4),
        });
      }
      return next;
    });
  };

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!query.trim()) return;
    runSearch(query, { addUserTurn: true });
    setQuery("");
  };

  const openRoute = (route: string) => {
    if (route.startsWith("http://") || route.startsWith("https://")) {
      window.open(route, "_blank", "noopener,noreferrer");
      return;
    }
    navigate(route);
  };

  const reportMissingHelp = (missingQuery: string) => {
    try {
      const key = "aq_missing_help_requests";
      const current = JSON.parse(window.localStorage.getItem(key) || "[]");
      const next = [
        {
          query: missingQuery,
          role: activeRole,
          route: location.pathname,
          createdAt: new Date().toISOString(),
        },
        ...current,
      ].slice(0, 100);
      window.localStorage.setItem(key, JSON.stringify(next));
    } catch {
      // Ignore storage errors and still acknowledge.
    }

    toast({
      title: "Missing topic noted",
      description: "Saved locally. Please share this with your product/admin team for docs updates.",
    });
  };

  const quickPrompts = useMemo(() => {
    if (activeRole === "all") {
      return [
        "How do I sign in securely?",
        "How do I review incident response lifecycle?",
        "How do I approve QR requests?",
        "How do policy alerts work?",
        "How does customer fraud reporting attach metadata?",
      ];
    }
    if (activeRole === "licensee") {
      return [
        "How do I sign in and reset my password?",
        "How do I request QR inventory?",
        "How do I use the batch workspace?",
        "How do I add a manufacturer account?",
        "How do I open a manufacturer's pending or printed batches?",
      ];
    }
    if (activeRole === "manufacturer") {
      return [
        "How do I sign in and install the connector?",
        "How do I create a print job?",
        "Which printers are supported?",
        "How do I use printer diagnostics?",
        "Why is a batch not visible to me?",
        "When does printed status update?",
      ];
    }
    return [
      "What does MSCQR confirmed this code again mean?",
      "What does Suspicious Duplicate mean?",
      "How do I claim ownership?",
      "How do I report suspected counterfeit?",
    ];
  }, [activeRole]);

  const activeRoleLabel = ROLE_LABELS[activeRole] || "General";

  return (
    <div className="fixed bottom-4 right-4 z-50 sm:bottom-5 sm:right-5">
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetTrigger asChild>
          <Button
            size="lg"
            className="h-12 rounded-full bg-slate-900 px-5 text-white shadow-lg hover:bg-slate-800"
          >
            <MessageCircleQuestion className="mr-2 h-4 w-4" />
            Help
          </Button>
        </SheetTrigger>

        <SheetContent
          side={isMobile ? "bottom" : "right"}
          className={
            isMobile
              ? "h-[86vh] rounded-t-2xl border-x-0 border-b-0 p-0"
              : "w-full max-w-[430px] p-0"
          }
        >
          <div className="flex h-full flex-col">
            <SheetHeader className="border-b px-4 py-3 text-left">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <SheetTitle className="flex items-center gap-2">
                    <CircleHelp className="h-4 w-4 text-cyan-700" />
                    Help & Fraud Assistant
                  </SheetTitle>
                  <SheetDescription>
                    Local assistant powered by approved help documentation only.
                  </SheetDescription>
                </div>
                <Badge variant="outline" className="text-[11px] uppercase tracking-wide">
                  {activeRoleLabel}
                </Badge>
              </div>
            </SheetHeader>

            <ScrollArea className="flex-1 px-4 py-4">
              <div className="space-y-3">
                {turns.map((turn) => {
                  if (turn.kind === "user") {
                    return (
                      <div key={turn.id} className="flex justify-end">
                        <div className="max-w-[88%] rounded-2xl bg-slate-900 px-3 py-2 text-sm text-white">
                          {turn.text}
                        </div>
                      </div>
                    );
                  }

                  if (turn.kind === "intro") {
                    return (
                      <div key={turn.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                        {turn.text}
                      </div>
                    );
                  }

                  if (turn.kind === "no_match") {
                    return (
                      <div key={turn.id} className="space-y-3 rounded-2xl border border-amber-200 bg-amber-50/70 p-3">
                        <div className="flex items-start gap-2">
                          <SearchX className="mt-0.5 h-4 w-4 text-amber-700" />
                          <div>
                            <p className="text-sm font-semibold text-amber-900">I couldn't find that yet</p>
                            <p className="text-xs text-amber-900/80">
                              Try one of these related guides.
                            </p>
                          </div>
                        </div>
                        <div className="grid gap-2">
                          {turn.suggestions.map((entry) => (
                            <Button
                              key={`${turn.id}-${entry.id}`}
                              type="button"
                              variant="outline"
                              className="justify-start text-left"
                              onClick={() => runSearch(entry.title, { addUserTurn: true })}
                            >
                              {entry.title}
                            </Button>
                          ))}
                        </div>
                        <Button
                          type="button"
                          variant="secondary"
                          className="w-full"
                          onClick={() => reportMissingHelp(turn.query)}
                        >
                          <Flag className="mr-2 h-4 w-4" />
                          Report missing help
                        </Button>
                      </div>
                    );
                  }

                  return (
                    <div key={turn.id} className="space-y-3 rounded-2xl border border-slate-200 bg-white p-3">
                      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                        Top matches for: {turn.query}
                      </p>
                      {turn.results.map((hit) => {
                        const cardKey = `${turn.id}-${hit.entry.id}`;
                        const expanded = Boolean(expandedCards[cardKey]);

                        return (
                          <div key={cardKey} className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
                            <div className="flex items-center justify-between gap-2">
                              <h4 className="text-sm font-semibold text-slate-900">{hit.entry.title}</h4>
                              <Badge variant="secondary" className="text-[10px] uppercase">
                                {ROLE_LABELS[hit.entry.role] || "General"}
                              </Badge>
                            </div>
                            <p className="mt-1 text-xs text-slate-600">{hit.shortAnswer}</p>

                            <Collapsible
                              open={expanded}
                              onOpenChange={(isOpen) =>
                                setExpandedCards((prev) => ({ ...prev, [cardKey]: isOpen }))
                              }
                              className="mt-2"
                            >
                              <CollapsibleTrigger asChild>
                                <Button type="button" variant="ghost" size="sm" className="px-0 text-cyan-700 hover:text-cyan-800">
                                  Read more
                                  {expanded ? (
                                    <ChevronUp className="ml-1 h-4 w-4" />
                                  ) : (
                                    <ChevronDown className="ml-1 h-4 w-4" />
                                  )}
                                </Button>
                              </CollapsibleTrigger>
                              <CollapsibleContent>
                                <div className="prose prose-sm mt-2 max-w-none text-slate-700">
                                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{hit.entry.answer}</ReactMarkdown>
                                </div>
                              </CollapsibleContent>
                            </Collapsible>

                            {hit.entry.linksToRoutes.length > 0 ? (
                              <div className="mt-3 flex flex-wrap gap-2">
                                {hit.entry.linksToRoutes.map((route) => (
                                  <Button
                                    key={`${cardKey}-${route}`}
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    onClick={() => openRoute(route)}
                                  >
                                    {routeLabel(route)}
                                    <MoveRight className="ml-1 h-3.5 w-3.5" />
                                  </Button>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  );
                })}

                {turns.length <= 1 ? (
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Quick prompts</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {quickPrompts.map((prompt) => (
                        <Button
                          key={prompt}
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => runSearch(prompt, { addUserTurn: true })}
                        >
                          {prompt}
                        </Button>
                      ))}
                    </div>
                  </div>
                ) : null}
                <div ref={endRef} />
              </div>
            </ScrollArea>

            <form onSubmit={onSubmit} className="border-t bg-white px-4 py-3">
              <div className="flex items-center gap-2">
                <Input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder={
                    activeRole === "all"
                      ? "Ask any workflow question..."
                      : activeRole === "licensee"
                      ? "Ask about requests, batches, tracking..."
                      : activeRole === "manufacturer"
                      ? "Ask about print jobs and batch flow..."
                      : "Ask about verify results or counterfeit reporting..."
                  }
                />
                <Button type="submit" className="bg-slate-900 text-white hover:bg-slate-800">
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </form>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
