import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

import {
  type ActiveSessionItem,
  type BrowserStorageSummary,
  type SessionSecuritySummary,
  formatIpReputation,
  formatRiskLevel,
  IP_REPUTATION_BADGE_CLASSNAME,
  RISK_BADGE_CLASSNAME,
} from "./types";

type SessionSecurityCardProps = {
  currentDeviceTrustLabel: string;
  currentSession: ActiveSessionItem | null;
  currentSessionSecurity: ActiveSessionItem["security"] | null;
  isAdminUser: boolean;
  loadSessions: () => Promise<void> | void;
  revokeAllLoading: boolean;
  revokeAllSessions: () => Promise<void> | void;
  revokeSession: (sessionId: string, current: boolean) => Promise<void> | void;
  revokingSessionId: string | null;
  sessionSecuritySummary: SessionSecuritySummary | null;
  sessions: ActiveSessionItem[];
  sessionsLoading: boolean;
  storagePostureHealthy: boolean;
  storageSummary: BrowserStorageSummary;
  userAuth?: {
    authAssurance?: string | null;
    mfaVerifiedAt?: string | null;
    sessionExpiresAt?: string | null;
    sessionId?: string | null;
    sessionStage?: string | null;
    stepUpMethod?: string | null;
    stepUpRequired?: boolean;
  } | null;
};

export function SessionSecurityCard({
  currentDeviceTrustLabel,
  currentSession,
  currentSessionSecurity,
  isAdminUser,
  loadSessions,
  revokeAllLoading,
  revokeAllSessions,
  revokeSession,
  revokingSessionId,
  sessionSecuritySummary,
  sessions,
  sessionsLoading,
  storagePostureHealthy,
  storageSummary,
  userAuth,
}: SessionSecurityCardProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="font-semibold">Account sessions</div>
        <div className="text-sm text-muted-foreground">
          Review active sessions, revoke stale devices, and check what this browser can still see locally.
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <Alert className={storagePostureHealthy ? "border-emerald-200 bg-emerald-50 text-emerald-950" : "border-amber-200 bg-amber-50 text-amber-950"}>
          <AlertDescription>
            Current device trust: <strong>{currentDeviceTrustLabel}</strong>.
            {userAuth?.mfaVerifiedAt ? ` Extra sign-in protection verified on ${new Date(userAuth.mfaVerifiedAt).toLocaleString()}.` : ""}
            {userAuth?.sessionExpiresAt ? ` Session refresh window ends ${new Date(userAuth.sessionExpiresAt).toLocaleString()}.` : ""}
            {currentSessionSecurity
              ? ` Current session risk is ${currentSessionSecurity.riskLevel.toLowerCase()} (${currentSessionSecurity.riskScore}/100) with ${formatIpReputation(currentSessionSecurity.internalIpReputation).replace("Network check: ", "")} network posture.`
              : ""}
            {sessionSecuritySummary?.possibleImpossibleTravel
              ? " MSCQR also detected a possible impossible-travel heuristic across active sessions."
              : ""}
            {!storagePostureHealthy
              ? " Browser-visible storage still needs attention before this device should be treated as fully clean."
              : " Browser-visible storage matches the hardened cookie-first model."}
          </AlertDescription>
        </Alert>

        <div className="grid gap-6 xl:grid-cols-[1.15fr,0.85fr]">
          <div className="space-y-4">
            <div className="rounded-xl border p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium">Active sessions</div>
                  <div className="text-sm text-muted-foreground">
                    These are live refresh-token chains that can continue renewing access until revoked or expired.
                  </div>
                </div>
                <Button variant="outline" onClick={() => void loadSessions()} disabled={sessionsLoading}>
                  {sessionsLoading ? "Refreshing..." : "Refresh"}
                </Button>
              </div>

              <div className="mt-4 space-y-3">
                {sessions.length ? (
                  sessions.map((session) => (
                    <div key={session.id} className="rounded-xl border bg-muted/20 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="font-medium">
                            {session.current ? "Current device" : "Other device"}
                            {session.mfaVerifiedAt ? " · extra protection verified" : ""}
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Badge variant="outline" className={RISK_BADGE_CLASSNAME[session.security.riskLevel]}>
                              {formatRiskLevel(session.security.riskLevel)} · {session.security.riskScore}/100
                            </Badge>
                            <Badge
                              variant="outline"
                              className={IP_REPUTATION_BADGE_CLASSNAME[session.security.internalIpReputation]}
                            >
                              {formatIpReputation(session.security.internalIpReputation)}
                            </Badge>
                            {session.security.possibleImpossibleTravel ? (
                              <Badge variant="outline" className="border-red-200 bg-red-50 text-red-900">
                                Impossible-travel heuristic
                              </Badge>
                            ) : null}
                          </div>
                          <details className="text-sm text-muted-foreground">
                            <summary className="cursor-pointer">Technical details</summary>
                            <div className="mt-1 break-all">{session.userAgent || "Browser details unavailable"}</div>
                          </details>
                          <div className="text-xs text-muted-foreground">
                            Started {new Date(session.createdAt).toLocaleString()}.
                            {session.lastUsedAt ? ` Last used ${new Date(session.lastUsedAt).toLocaleString()}.` : ""}
                            {session.expiresAt ? ` Expires ${new Date(session.expiresAt).toLocaleString()}.` : ""}
                          </div>
                          {session.ipHash ? (
                            <details className="text-xs text-muted-foreground">
                              <summary className="cursor-pointer">Network detail</summary>
                              <div className="mt-1 break-all">{session.ipHash}</div>
                            </details>
                          ) : null}
                          {session.security.possibleImpossibleTravelReason ? (
                            <div className="text-xs text-red-900">{session.security.possibleImpossibleTravelReason}</div>
                          ) : null}
                          {session.security.riskReasons.length ? (
                            <div className="pt-1 text-xs text-muted-foreground">
                              Why this was scored: {session.security.riskReasons.slice(0, 3).join(" ")}
                            </div>
                          ) : null}
                        </div>
                        <Button
                          variant={session.current ? "destructive" : "outline"}
                          size="sm"
                          disabled={revokingSessionId === session.id || revokeAllLoading}
                          onClick={() => void revokeSession(session.id, session.current)}
                        >
                          {revokingSessionId === session.id ? "Revoking..." : session.current ? "Sign out this device" : "Revoke"}
                        </Button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-xl border border-dashed p-4 text-sm text-muted-foreground">
                    {sessionsLoading ? "Loading active sessions..." : "No active refresh sessions were returned for this account."}
                  </div>
                )}
              </div>

              <div className="mt-4 flex flex-wrap justify-end gap-3">
                <Button variant="destructive" onClick={() => void revokeAllSessions()} disabled={revokeAllLoading || sessionsLoading || !sessions.length}>
                  {revokeAllLoading ? "Revoking all..." : "Revoke all sessions"}
                </Button>
              </div>
            </div>

            <div className="rounded-xl border p-4">
              <div className="font-medium">Current device trust details</div>
              <div className="mt-2 space-y-2 text-sm text-muted-foreground">
                <div>Support reference: {userAuth?.sessionId || currentSession?.id || "Unavailable"}</div>
                <div>Sign-in status: {userAuth?.authAssurance === "ADMIN_MFA" ? "Extra protection verified" : "Password verified"}</div>
                <div>Step-up status: {userAuth?.stepUpRequired ? `Required (${userAuth.stepUpMethod || "unknown method"})` : "Satisfied"}</div>
                <div>Active session count: {sessions.length}</div>
                <div>
                  Current session risk:{" "}
                  {currentSessionSecurity
                    ? `${formatRiskLevel(currentSessionSecurity.riskLevel)} (${currentSessionSecurity.riskScore}/100)`
                    : "Unavailable"}
                </div>
                <div>
                  Current network posture:{" "}
                  {currentSessionSecurity
                    ? formatIpReputation(currentSessionSecurity.internalIpReputation).replace("Network check: ", "")
                    : "Unavailable"}
                </div>
                <div>
                  Impossible-travel heuristic: {currentSessionSecurity?.possibleImpossibleTravel ? "Flagged for review" : "Not detected"}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-xl border p-4">
              <div className="font-medium">Session risk summary</div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Highest active risk</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary
                      ? `${formatRiskLevel(sessionSecuritySummary.highestRiskLevel)} (${sessionSecuritySummary.highestRiskScore}/100)`
                      : "Unavailable"}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Elevated or worse</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary ? `${sessionSecuritySummary.elevatedRiskSessionCount} session(s)` : "Unavailable"}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Distinct networks (24h)</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary ? sessionSecuritySummary.distinctIpHashes24h : "Unavailable"}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Overall network posture</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary
                      ? formatIpReputation(sessionSecuritySummary.internalIpReputation).replace("Network check: ", "")
                      : "Unavailable"}
                  </div>
                </div>
              </div>
              <div className="mt-3 text-sm text-muted-foreground">
                {sessionSecuritySummary?.possibleImpossibleTravel
                  ? "Possible impossible-travel activity was detected, which means multiple active sessions changed network fingerprints unusually quickly. This is a heuristic and should trigger review, not blind account lockout."
                  : "No impossible-travel heuristic is active across the current session set."}
              </div>
            </div>

            <div className="rounded-xl border p-4">
              <div className="font-medium">Browser storage summary</div>
              <div className="mt-2 text-sm text-muted-foreground">
                MSCQR stores the main sign-in session in protected browser cookies. The lists below show only browser-visible state on this device.
              </div>
              <div className="mt-4 space-y-3 text-sm">
                <div>
                  <div className="font-medium">Visible cookie names</div>
                  <div className="mt-1 text-muted-foreground">
                    {storageSummary.cookieNames.length
                      ? storageSummary.cookieNames.join(", ")
                      : "No browser-visible cookies are exposed in this tab."}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Local storage keys</div>
                  <div className="mt-1 text-muted-foreground">
                    {storageSummary.localStorageKeys.length
                      ? storageSummary.localStorageKeys.join(", ")
                      : "No localStorage keys detected."}
                  </div>
                </div>
                <div>
                  <div className="font-medium">Session storage keys</div>
                  <div className="mt-1 text-muted-foreground">
                    {storageSummary.sessionStorageKeys.length
                      ? storageSummary.sessionStorageKeys.join(", ")
                      : "No sessionStorage keys detected."}
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border p-4">
              <div className="font-medium">Plain-English storage posture</div>
              <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
                <li>Admin and workspace sessions should stay in protected cookies, not browser storage.</li>
                <li>Browser storage should be limited to UI preferences, printing helpers, and short-lived verification continuity.</li>
                <li>Use “Revoke all sessions” after device loss, contractor offboarding, or any suspicious sign-in pattern.</li>
              </ul>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
