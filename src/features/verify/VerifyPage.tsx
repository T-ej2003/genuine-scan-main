import VerifyExperience from "@/features/verify/components/VerifyExperience";
import { LegalFooter } from "@/components/trust/LegalFooter";

export default function VerifyPage() {
  return (
    <div className="min-h-screen bg-background">
      <VerifyExperience />
      <LegalFooter className="mt-8" />
    </div>
  );
}
