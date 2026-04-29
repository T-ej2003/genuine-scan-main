import { Alert, AlertDescription } from "@/components/ui/alert";
import { ActionButton } from "@/components/ui/action-button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createUiActionState } from "@/lib/ui-actions";

type PasswordSettingsCardProps = {
  changePassword: (event: React.FormEvent) => Promise<void> | void;
  confirmNewPassword: string;
  currentPassword: string;
  newPassword: string;
  passwordLoading: boolean;
  setConfirmNewPassword: (value: string) => void;
  setCurrentPassword: (value: string) => void;
  setNewPassword: (value: string) => void;
  stepUpMethod?: string | null;
  stepUpRequired?: boolean;
};

export function PasswordSettingsCard({
  changePassword,
  confirmNewPassword,
  currentPassword,
  newPassword,
  passwordLoading,
  setConfirmNewPassword,
  setCurrentPassword,
  setNewPassword,
  stepUpMethod,
  stepUpRequired,
}: PasswordSettingsCardProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="font-semibold">Security</div>
        <div className="text-sm text-muted-foreground">Change your password. You will need your current password.</div>
      </CardHeader>
      <CardContent>
        {stepUpRequired ? (
          <Alert className="mb-4 border-amber-200 bg-amber-50 text-amber-950">
            <AlertDescription>
              Sensitive actions are locked until you confirm{" "}
              {stepUpMethod === "ADMIN_MFA" ? "your extra sign-in protection code" : "your current password"} again.
            </AlertDescription>
          </Alert>
        ) : null}
        <form className="space-y-4" onSubmit={changePassword}>
          <div className="space-y-2">
            <Label>Current password</Label>
            <Input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
          </div>

          <div className="space-y-2">
            <Label>New password</Label>
            <Input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          </div>

          <div className="space-y-2">
            <Label>Confirm new password</Label>
            <Input type="password" value={confirmNewPassword} onChange={(event) => setConfirmNewPassword(event.target.value)} />
          </div>

          <div className="flex justify-end">
            <ActionButton
              data-testid="account-change-password"
              type="submit"
              state={
                passwordLoading
                  ? createUiActionState("pending", "Saving your new password now.")
                  : createUiActionState("enabled")
              }
              idleLabel="Update password"
              pendingLabel="Updating..."
              showReasonBelow={false}
            />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
