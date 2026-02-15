import React, { useMemo } from "react";
import { CheckSquare, Camera } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { ScreenshotSpec } from "@/lib/help-docs";

export function ScreenshotsChecklist({ screenshots }: { screenshots: ScreenshotSpec[] }) {
  const unique = useMemo(() => {
    const byFile = new Map<string, ScreenshotSpec>();
    for (const shot of screenshots) {
      if (!byFile.has(shot.file)) byFile.set(shot.file, shot);
    }
    return Array.from(byFile.values()).sort((a, b) => a.file.localeCompare(b.file));
  }, [screenshots]);

  if (unique.length === 0) return null;

  return (
    <Alert className="border-sky-200 bg-sky-50 text-sky-900">
      <Camera className="h-4 w-4 text-sky-700" />
      <AlertTitle>Screenshots needed</AlertTitle>
      <AlertDescription>
        <div className="mt-3 space-y-2">
          {unique.map((shot) => (
            <div key={shot.file} className="flex items-start gap-2 text-sm">
              <CheckSquare className="mt-0.5 h-4 w-4 text-sky-700" />
              <div>
                <p className="font-mono text-xs text-sky-900">{shot.file}</p>
                <p className="text-xs text-sky-800/90">{shot.capture}</p>
              </div>
            </div>
          ))}
        </div>
      </AlertDescription>
    </Alert>
  );
}
