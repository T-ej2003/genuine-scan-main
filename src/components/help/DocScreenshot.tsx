import React, { useMemo, useState } from "react";
import { Image as ImageIcon } from "lucide-react";

import type { ScreenshotSpec } from "@/lib/help-docs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

export function DocScreenshot({ screenshot }: { screenshot: ScreenshotSpec }) {
  const [missing, setMissing] = useState(false);
  const src = useMemo(() => `/docs/${encodeURIComponent(screenshot.file)}`, [screenshot.file]);

  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-slate-200 bg-slate-50 p-2">
        {!missing ? (
          <Dialog>
            <DialogTrigger asChild>
              <button
                type="button"
                className="group relative block w-full"
                aria-label={`Open screenshot: ${screenshot.file}`}
              >
                <img
                  src={src}
                  alt={screenshot.alt}
                  loading="lazy"
                  onError={() => setMissing(true)}
                  className="h-auto w-full rounded-md border border-slate-200 bg-white object-cover"
                />
                <span className="pointer-events-none absolute right-2 top-2 rounded-md bg-slate-900/80 px-2 py-1 text-[11px] font-medium text-white opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                  Click to zoom
                </span>
              </button>
            </DialogTrigger>
            <DialogContent className="max-w-5xl p-4">
              <DialogHeader className="space-y-1">
                <DialogTitle className="text-base">{screenshot.alt}</DialogTitle>
                <p className="font-mono text-xs text-muted-foreground">{screenshot.file}</p>
              </DialogHeader>
              <div className="rounded-lg border bg-white p-2">
                <img src={src} alt={screenshot.alt} className="h-auto w-full rounded-md object-contain" />
              </div>
              <p className="text-sm text-slate-600">
                <span className="font-semibold text-slate-800">Capture:</span> {screenshot.capture}
              </p>
            </DialogContent>
          </Dialog>
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
