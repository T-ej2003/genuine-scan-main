import { Link } from "react-router-dom";

export function ComplianceStatements() {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4">
      <p className="text-sm text-slate-700">
        Need compliance, privacy, retention, or security details? Review the{" "}
        <Link to="/privacy" className="font-medium text-primary underline underline-offset-4">
          Privacy Notice
        </Link>{" "}
        and{" "}
        <Link to="/trust" className="font-medium text-primary underline underline-offset-4">
          Trust & Security
        </Link>{" "}
        pages.
      </p>
    </section>
  );
}
