import { cn } from "@/lib/utils";

type ConnectorReleaseDiagnosticsProps = {
  availableVersion: string;
  requiredProtocol: string;
  installedVersion: string;
  reachable: boolean;
  updateRequired: boolean;
};

export function ConnectorReleaseDiagnostics({
  availableVersion,
  requiredProtocol,
  installedVersion,
  reachable,
  updateRequired,
}: ConnectorReleaseDiagnosticsProps) {
  const cells = [
    ["Available", availableVersion || "Latest release", ""],
    ["Required protocol", requiredProtocol, "break-all"],
    ["Installed", installedVersion, ""],
    ["Update required", updateRequired ? "Yes" : reachable ? "No" : "Unknown", updateRequired ? "text-amber-700" : "text-emerald-700"],
  ];

  return (
    <div className="mt-5 grid gap-3 md:grid-cols-4">
      {cells.map(([label, value, valueClass]) => (
        <div key={label} className="rounded-[20px] border border-slate-200 bg-white/85 px-4 py-3 text-sm">
          <div className="text-xs uppercase tracking-[0.16em] text-slate-400">{label}</div>
          <div className={cn("mt-1 font-semibold text-slate-950", valueClass)}>{value}</div>
        </div>
      ))}
    </div>
  );
}
