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
import { supportReferenceLabel } from "@/lib/audit-display";

type SessionSecurityCardProps = {
  currentDeviceTrustLabel: string;
  currentSession: ActiveSessionItem | null;
  currentSessionSecurity: ActiveSessionItem["security"] | null;
  isAdminUser: boolean;
  isPlatformAdmin?: boolean;
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
  isPlatformAdmin = false,
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
          Review active sessions and sign out devices you no longer use.
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <Alert className={storagePostureHealthy ? "border-emerald-200 bg-emerald-50 text-emerald-950" : "border-amber-200 bg-amber-50 text-amber-950"}>
          <AlertDescription>
            This device is <strong>{currentDeviceTrustLabel.toLowerCase()}</strong>.
            {userAuth?.mfaVerifiedAt ? ` Extra sign-in protection verified on ${new Date(userAuth.mfaVerifiedAt).toLocaleString()}.` : ""}
            {userAuth?.sessionExpiresAt ? ` Session renewal is available until ${new Date(userAuth.sessionExpiresAt).toLocaleString()}.` : ""}
            {currentSessionSecurity?.possibleImpossibleTravel || sessionSecuritySummary?.possibleImpossibleTravel
              ? " One session needs review because it changed location unusually quickly."
              : " No unusual account session activity is visible."}
          </AlertDescription>
        </Alert>

        <div className="grid gap-6 xl:grid-cols-[1.15fr,0.85fr]">
          <div className="space-y-4">
            <div className="rounded-xl border p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium">Active sessions</div>
                  <div className="text-sm text-muted-foreground">
                    These devices can stay signed in until they expire or you sign them out.
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
                              {session.security.riskLevel === "LOW" ? "Looks normal" : "Needs review"}
                            </Badge>
                            <Badge
                              variant="outline"
                              className={IP_REPUTATION_BADGE_CLASSNAME[session.security.internalIpReputation]}
                            >
                              {session.security.internalIpReputation === "trusted" ? "Known network" : "Network checked"}
                            </Badge>
                            {session.security.possibleImpossibleTravel ? (
                              <Badge variant="outline" className="border-red-200 bg-red-50 text-red-900">
                                Review location
                              </Badge>
                            ) : null}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Started {new Date(session.createdAt).toLocaleString()}.
                            {session.lastUsedAt ? ` Last used ${new Date(session.lastUsedAt).toLocaleString()}.` : ""}
                            {session.expiresAt ? ` Expires ${new Date(session.expiresAt).toLocaleString()}.` : ""}
                          </div>
                          {session.security.possibleImpossibleTravelReason ? (
                            <div className="text-xs text-red-900">Review this session before continuing sensitive work.</div>
                          ) : null}
                        </div>
                        <Button
                          variant={session.current ? "destructive" : "outline"}
                          size="sm"
                          disabled={revokingSessionId === session.id || revokeAllLoading}
                          onClick={() => void revokeSession(session.id, session.current)}
                        >
                          {revokingSessionId === session.id ? "Signing out..." : session.current ? "Sign out this device" : "Sign out"}
                        </Button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-xl border border-dashed p-4 text-sm text-muted-foreground">
                    {sessionsLoading ? "Loading active sessions..." : "No active sessions were found for this account."}
                  </div>
                )}
              </div>

              <div className="mt-4 flex flex-wrap justify-end gap-3">
                <Button variant="destructive" onClick={() => void revokeAllSessions()} disabled={revokeAllLoading || sessionsLoading || !sessions.length}>
                  {revokeAllLoading ? "Signing out..." : "Sign out all devices"}
                </Button>
              </div>
            </div>

            <div className="rounded-xl border p-4">
              <div className="font-medium">Current device</div>
              <div className="mt-2 space-y-2 text-sm text-muted-foreground">
                <div>This device is verified for your account.</div>
                <div>Sign-in status: {userAuth?.authAssurance === "ADMIN_MFA" ? "Extra protection verified" : "Password verified"}</div>
                <div>Active sessions: {sessions.length.toLocaleString()}</div>
                <div>Account protection: {userAuth?.stepUpRequired ? "Additional verification required" : "Ready"}</div>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-xl border p-4">
              <div className="font-medium">Session health</div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Overall status</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary?.elevatedRiskSessionCount ? "Needs review" : "Looks normal"}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Devices to review</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessionSecuritySummary ? `${sessionSecuritySummary.elevatedRiskSessionCount} session(s)` : "0 sessions"}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Active sessions</div>
                  <div className="mt-1 text-lg font-semibold">
                    {sessions.length.toLocaleString()}
                  </div>
                </div>
                <div className="rounded-xl border bg-muted/20 p-3">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Storage check</div>
                  <div className="mt-1 text-lg font-semibold">
                    {storagePostureHealthy ? "Clean" : "Review"}
                  </div>
                </div>
              </div>
              <div className="mt-3 text-sm text-muted-foreground">
                {sessionSecuritySummary?.possibleImpossibleTravel
                  ? "One or more sessions changed location unusually quickly. Sign out devices you do not recognize."
                  : "No unusual session movement is visible across your account."}
              </div>
            </div>

            <div className="rounded-xl border p-4">
              <div className="font-medium">Account safety tips</div>
              <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
                <li>Sign out all devices after device loss, contractor offboarding, or a suspicious sign-in.</li>
                <li>Keep extra sign-in protection enabled for admin accounts.</li>
                <li>Review this page periodically when your team changes devices.</li>
              </ul>
            </div>

            {isPlatformAdmin ? (
              <details className="rounded-xl border p-4 text-sm text-muted-foreground">
                <summary className="cursor-pointer font-medium text-foreground">Advanced diagnostics</summary>
                <div className="mt-3 grid gap-2">
                  <div>Support code: {supportReferenceLabel(userAuth?.sessionId || currentSession?.id, "Session")}</div>
                  <div>
                    Session posture:{" "}
                    {currentSessionSecurity
                      ? `${formatRiskLevel(currentSessionSecurity.riskLevel)} / ${formatIpReputation(currentSessionSecurity.internalIpReputation)}`
                      : "Unavailable"}
                  </div>
                  <div>Cookie entries visible to this browser: {storageSummary.cookieNames.length}</div>
                  <div>Local storage entries: {storageSummary.localStorageKeys.length}</div>
                  <div>Session storage entries: {storageSummary.sessionStorageKeys.length}</div>
                </div>
              </details>
            ) : null}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
