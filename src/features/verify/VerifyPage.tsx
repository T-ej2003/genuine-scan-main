import { useLocation } from "react-router-dom";

import VerifyExperience from "@/features/verify/components/VerifyExperience";
import { LegalFooter } from "@/components/trust/LegalFooter";
import VerifyLanding from "@/pages/VerifyLanding";

export default function VerifyPage() {
  const location = useLocation();
  const scanToken = new URLSearchParams(location.search).get("t");

  if (location.pathname === "/scan" && !scanToken) {
    return <VerifyLanding />;
  }

  return (
    <div className="dark min-h-screen bg-mscqr-background text-mscqr-primary">
      <VerifyExperience />
      <LegalFooter tone="dark" className="mt-8 bg-mscqr-background" />
    </div>
  );
}
