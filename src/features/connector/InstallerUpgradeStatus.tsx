import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { authorizeInstallerUpgrade } from "./authorizeInstallerUpgrade";

const success = "Upgrade verified. Eligible printing can resume; uncertain attempts remain protected.";

export function InstallerUpgradeStatus({ pairingId }: { pairingId: string | null }) {
  const [state, setState] = useState("Authorizing the signed connector upgrade…");
  useEffect(() => {
    if (!pairingId) return;
    if (!/^[0-9a-f-]{36}$/i.test(pairingId)) { setState("Invalid installer pairing."); return; }
    let cancelled = false;
    const abort = new AbortController();
    void authorizeInstallerUpgrade(pairingId, abort.signal).then(() => {
      if (!cancelled) setState(success);
    }).catch((error: Error) => {
      if (!cancelled) setState(error.message || "Upgrade authorization failed. Your existing installation is unchanged.");
    });
    return () => { cancelled = true; abort.abort(); };
  }, [pairingId]);
  if (!pairingId) return null;
  return <Alert>
    <ShieldCheck className="h-4 w-4" />
    <AlertTitle>Connector upgrade</AlertTitle>
    <AlertDescription>{state}
      {state !== success && !state.startsWith("Authorizing") ? <Button asChild size="sm" className="ml-3">
        <Link to={`/login?returnTo=${encodeURIComponent(`/connector-download?upgradePairing=${pairingId}`)}`}>Sign in to continue</Link>
      </Button> : null}
    </AlertDescription>
  </Alert>;
}
