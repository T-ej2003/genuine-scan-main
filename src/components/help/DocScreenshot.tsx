import React, { useMemo, useState } from "react";
import { Image as ImageIcon } from "lucide-react";

import type { ScreenshotSpec } from "@/lib/help-docs";

export function DocScreenshot({ screenshot }: { screenshot: ScreenshotSpec }) {
  const [missing, setMissing] = useState(false);
  const src = useMemo(() => `/docs/${encodeURIComponent(screenshot.file)}`, [screenshot.file]);

  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-slate-200 bg-slate-50 p-2">
        {!missing ? (
          <img
            src={src}
            alt={screenshot.alt}
            loading="lazy"
            onError={() => setMissing(true)}
            className="h-auto w-full rounded-md border border-slate-200 bg-white object-cover"
          />
        ) : (
          <div className="flex min-h-48 w-full flex-col items-center justify-center rounded-md border border-dashed border-slate-300 bg-white px-4 text-center">
            <ImageIcon className="mb-2 h-6 w-6 text-slate-400" />
            <p className="text-sm font-medium text-slate-700">Screenshot placeholder</p>
            <p className="mt-1 font-mono text-xs text-slate-600">{screenshot.file}</p>
            <p className="mt-2 text-xs text-slate-500">Add file at `/public/docs/{screenshot.file}`</p>
          </div>
        )}
      </div>

      <p className="text-xs text-slate-500">
        <span className="font-medium text-slate-700">Capture:</span> {screenshot.capture}
      </p>

      {screenshot.note ? <p className="text-xs text-slate-500">Note: {screenshot.note}</p> : null}
    </div>
  );
}
