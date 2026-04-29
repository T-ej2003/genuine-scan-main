import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import type { AdminMfaStatus } from "./types";

type AdminMfaCardProps = {
  beginMfaSetup: () => Promise<void> | void;
  beginWebAuthnSetup: () => Promise<void> | void;
  confirmMfaSetup: (event: React.FormEvent) => Promise<void> | void;
  disableMfa: () => Promise<void> | void;
  disablePassword: string;
  disableCode: string;
  isAdminUser: boolean;
  mfaCode: string;
  mfaLoading: boolean;
  mfaQrDataUrl: string;
  mfaRotateCode: string;
  mfaSetup: { secret: string; otpauthUri: string; backupCodes: string[] } | null;
  mfaStatus: AdminMfaStatus | null;
  onDisableCodeChange: (value: string) => void;
  onDisablePasswordChange: (value: string) => void;
  onMfaCodeChange: (value: string) => void;
  onRotateCodeChange: (value: string) => void;
  onSetMfaSetup: (value: { secret: string; otpauthUri: string; backupCodes: string[] } | null) => void;
  onWebauthnLabelChange: (value: string) => void;
  removeWebAuthnCredential: (credentialId: string) => Promise<void> | void;
  removingWebAuthnId: string | null;
  rotateBackupCodes: () => Promise<void> | void;
  rotatedBackupCodes: string[] | null;
  verifyWithWebAuthn: () => Promise<void> | void;
  webauthnAvailable: boolean;
  webauthnLabel: string;
};

export function AdminMfaCard({
  beginMfaSetup,
  beginWebAuthnSetup,
  confirmMfaSetup,
  disableMfa,
  disablePassword,
  disableCode,
  isAdminUser,
  mfaCode,
  mfaLoading,
  mfaQrDataUrl,
  mfaRotateCode,
  mfaSetup,
  mfaStatus,
  onDisableCodeChange,
  onDisablePasswordChange,
  onMfaCodeChange,
  onRotateCodeChange,
  onSetMfaSetup,
  onWebauthnLabelChange,
  removeWebAuthnCredential,
  removingWebAuthnId,
  rotateBackupCodes,
  rotatedBackupCodes,
  verifyWithWebAuthn,
  webauthnAvailable,
  webauthnLabel,
}: AdminMfaCardProps) {
  if (!isAdminUser) {
    return null;
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="font-semibold">Extra sign-in protection</div>
        <div className="text-sm text-muted-foreground">Sensitive admin actions stay locked behind a recent confirmation.</div>
      </CardHeader>
      <CardContent className="space-y-6">
        {mfaStatus ? (
          <Alert>
            <AlertDescription>
              {mfaStatus.enabled
                ? `Extra sign-in protection is enabled. Backup codes remaining: ${mfaStatus.backupCodesRemaining ?? 0}.`
                : "Extra sign-in protection is not enabled for this admin account yet."}
              {mfaStatus.preferredMethod
                ? ` Preferred method: ${mfaStatus.preferredMethod === "WEBAUTHN" ? "Passkey or security key" : "Authenticator app"}.`
                : ""}
              {mfaStatus.lastUsedAt ? ` Last used: ${new Date(mfaStatus.lastUsedAt).toLocaleString()}.` : ""}
            </AlertDescription>
          </Alert>
        ) : null}

        {!mfaStatus?.enabled ? (
          <div className="space-y-4">
            {!mfaSetup ? (
              <Button onClick={() => void beginMfaSetup()} disabled={mfaLoading}>
                {mfaLoading ? "Preparing..." : "Set up extra protection"}
              </Button>
            ) : (
              <form className="space-y-4" onSubmit={confirmMfaSetup}>
                {mfaQrDataUrl ? <img src={mfaQrDataUrl} alt="Extra sign-in protection QR code" className="h-52 w-52 rounded-xl border p-2" /> : null}
                <div className="space-y-2">
                  <Label>Manual setup key</Label>
                  <Input value={mfaSetup.secret} readOnly className="font-mono text-sm" />
                </div>
                <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
                  <div className="font-medium">Backup codes</div>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    {mfaSetup.backupCodes.map((code) => (
                      <div key={code} className="rounded-lg border border-amber-200 bg-white px-3 py-2 font-mono text-xs">
                        {code}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Authenticator code</Label>
                  <Input value={mfaCode} onChange={(event) => onMfaCodeChange(event.target.value)} placeholder="123456" />
                </div>
                <div className="flex justify-end gap-3">
                  <Button type="button" variant="outline" onClick={() => onSetMfaSetup(null)} disabled={mfaLoading}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={mfaLoading}>
                    {mfaLoading ? "Confirming..." : "Enable extra protection"}
                  </Button>
                </div>
              </form>
            )}
          </div>
        ) : (
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="space-y-3 rounded-xl border p-4">
              <div className="font-medium">Passkeys and security keys</div>
              <div className="text-sm text-muted-foreground">
                Prefer passkeys when this browser supports them. Authenticator codes stay available as a fallback.
              </div>
              {webauthnAvailable ? (
                <>
                  <div className="space-y-2">
                    <Label>Device label</Label>
                    <Input
                      value={webauthnLabel}
                      onChange={(event) => onWebauthnLabelChange(event.target.value)}
                      placeholder="Factory MacBook or Security key"
                    />
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => void beginWebAuthnSetup()} disabled={mfaLoading}>
                      {mfaLoading ? "Preparing..." : "Add passkey"}
                    </Button>
                    {mfaStatus?.hasWebAuthn ? (
                      <Button variant="outline" onClick={() => void verifyWithWebAuthn()} disabled={mfaLoading}>
                        {mfaLoading ? "Waiting..." : "Verify with passkey"}
                      </Button>
                    ) : null}
                  </div>
                </>
              ) : (
                <div className="text-sm text-muted-foreground">
                  This browser does not support passkeys. You can still use the authenticator-app flow below.
                </div>
              )}

              {mfaStatus?.webauthnCredentials?.length ? (
                <div className="space-y-3">
                  {mfaStatus.webauthnCredentials.map((credential) => (
                    <div key={credential.id} className="rounded-xl border bg-muted/30 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="font-medium">{credential.label}</div>
                          <div className="text-xs text-muted-foreground">
                            {(credential.transports || []).length
                              ? "Passkey available on this device."
                              : "Passkey enrolled."}
                            {credential.lastUsedAt ? ` Last used ${new Date(credential.lastUsedAt).toLocaleString()}.` : ""}
                          </div>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={removingWebAuthnId === credential.id}
                          onClick={() => void removeWebAuthnCredential(credential.id)}
                        >
                          {removingWebAuthnId === credential.id ? "Removing..." : "Remove"}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">No passkeys are enrolled yet.</div>
              )}
            </div>

            <div className="space-y-3 rounded-xl border p-4">
              <div className="font-medium">Rotate backup codes</div>
              <div className="text-sm text-muted-foreground">
                Enter a current authenticator or backup code to issue a fresh backup-code set.
              </div>
              <Label>Current protection code</Label>
              <Input value={mfaRotateCode} onChange={(event) => onRotateCodeChange(event.target.value)} placeholder="123456 or ABCDE-12345" />
              <Button onClick={() => void rotateBackupCodes()} disabled={mfaLoading}>
                {mfaLoading ? "Rotating..." : "Rotate backup codes"}
              </Button>
              {rotatedBackupCodes?.length ? (
                <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                  <div className="font-medium text-amber-950">New backup codes</div>
                  <div className="mt-3 grid grid-cols-2 gap-2">
                    {rotatedBackupCodes.map((code) => (
                      <div key={code} className="rounded-lg border border-amber-200 bg-white px-3 py-2 font-mono text-xs">
                        {code}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="space-y-3 rounded-xl border border-red-200 p-4">
              <div className="font-medium text-red-900">Turn off extra protection</div>
              <div className="text-sm text-red-900/80">
                This is only for controlled recovery. The next admin sign-in will require setup again.
              </div>
              <div className="space-y-2">
                <Label>Current password</Label>
                <Input type="password" value={disablePassword} onChange={(event) => onDisablePasswordChange(event.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>Current protection code</Label>
                <Input value={disableCode} onChange={(event) => onDisableCodeChange(event.target.value)} placeholder="123456 or ABCDE-12345" />
              </div>
              <Button variant="destructive" onClick={() => void disableMfa()} disabled={mfaLoading}>
                {mfaLoading ? "Disabling..." : "Turn off extra protection"}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
