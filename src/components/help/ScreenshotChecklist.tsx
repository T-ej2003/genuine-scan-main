import React from "react";
import { Camera } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export type ScreenshotNeed = {
  filename: string;
  whereToCapture: string;
  usedIn?: string;
};

export function ScreenshotChecklist({ items }: { items: ScreenshotNeed[] }) {
  if (!items || items.length === 0) return null;

  return (
    <Alert className="border-sky-200 bg-sky-50 text-sky-950">
      <Camera className="h-4 w-4 text-sky-700" />
      <AlertTitle>Screenshots needed</AlertTitle>
      <AlertDescription>
        <p className="mb-3 text-sm text-sky-900/90">
          Add files to <span className="font-mono">public/docs/</span>. Help pages render real images automatically when present.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {items.map((item) => (
            <div key={item.filename} className="rounded-lg border border-sky-200 bg-white/70 p-3">
              <p className="font-mono text-xs font-semibold text-sky-950">{item.filename}</p>
              <p className="mt-1 text-xs text-sky-900/80">{item.whereToCapture}</p>
              {item.usedIn ? <p className="mt-1 text-[11px] text-sky-900/70">Used in: {item.usedIn}</p> : null}
            </div>
          ))}
        </div>
      </AlertDescription>
    </Alert>
  );
}

