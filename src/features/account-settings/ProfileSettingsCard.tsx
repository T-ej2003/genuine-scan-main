import { ActionButton } from "@/components/ui/action-button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createUiActionState } from "@/lib/ui-actions";

type ProfileSettingsCardProps = {
  email: string;
  name: string;
  onSubmit: (event: React.FormEvent) => Promise<void> | void;
  profileLoading: boolean;
  setEmail: (value: string) => void;
  setName: (value: string) => void;
  user: {
    emailVerifiedAt?: string | null;
    pendingEmail?: string | null;
  } | null;
};

export function ProfileSettingsCard({
  email,
  name,
  onSubmit,
  profileLoading,
  setEmail,
  setName,
  user,
}: ProfileSettingsCardProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="font-semibold">Profile</div>
        <div className="text-sm text-muted-foreground">
          Update your name. Email changes stay pending until you confirm them from your inbox.
        </div>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={onSubmit}>
          <div className="space-y-2">
            <Label>Name</Label>
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" />
          </div>

          <div className="space-y-2">
            <Label>Email</Label>
            <Input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" />
            {user?.pendingEmail ? (
              <p className="text-sm text-amber-700">
                Pending change: <strong>{user.pendingEmail}</strong>. Open the verification email to finish this update.
              </p>
            ) : user?.emailVerifiedAt ? (
              <p className="text-sm text-muted-foreground">Verified on {new Date(user.emailVerifiedAt).toLocaleString()}.</p>
            ) : (
              <p className="text-sm text-amber-700">This account email is not verified yet.</p>
            )}
          </div>

          <div className="flex justify-end">
            <ActionButton
              data-testid="account-save-profile"
              type="submit"
              state={profileLoading ? createUiActionState("pending", "Saving your latest profile details.") : createUiActionState("enabled")}
              idleLabel="Save changes"
              pendingLabel="Saving..."
              showReasonBelow={false}
            />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
