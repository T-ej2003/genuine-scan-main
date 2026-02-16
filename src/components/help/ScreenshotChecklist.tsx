import React, { useEffect, useMemo, useState } from "react";
import { Camera } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export type ScreenshotNeed = {
  filename: string;
  whereToCapture: string;
  usedIn?: string;
};

const screenshotAvailability = new Map<string, boolean | Promise<boolean>>();

const fileExists = async (filename: string) => {
  const normalizedFilename = String(filename || "").trim();
  if (!normalizedFilename) return false;

  const cached = screenshotAvailability.get(normalizedFilename);
  if (typeof cached === "boolean") return cached;
  if (cached) return cached;

  const src = `/docs/${normalizedFilename}`.replace(/\/{2,}/g, "/");
  const probe = new Promise<boolean>((resolve) => {
    const image = new Image();
    image.onload = () => resolve(true);
    image.onerror = () => resolve(false);
    image.src = src;
  }).then((exists) => {
    screenshotAvailability.set(normalizedFilename, exists);
    return exists;
  });

  screenshotAvailability.set(normalizedFilename, probe);
  return probe;
};

export function ScreenshotChecklist({ items }: { items: ScreenshotNeed[] }) {
  const normalizedItems = useMemo(
    () =>
      (items || []).filter((item) => {
        const filename = String(item?.filename || "").trim();
        return filename.length > 0;
      }),
    [items]
  );

  const [missingByFile, setMissingByFile] = useState<Record<string, boolean> | null>(null);

  useEffect(() => {
    let cancelled = false;

    if (normalizedItems.length === 0) {
      setMissingByFile({});
      return () => {
        cancelled = true;
      };
    }

    (async () => {
      const checks = await Promise.all(
        normalizedItems.map(async (item) => ({
          filename: item.filename,
          exists: await fileExists(item.filename),
        }))
      );
      if (cancelled) return;
      const next = Object.fromEntries(checks.map((entry) => [entry.filename, !entry.exists]));
      setMissingByFile(next);
    })();

    return () => {
      cancelled = true;
    };
  }, [normalizedItems]);

  const missingItems = useMemo(() => {
    if (!missingByFile) return [];
    return normalizedItems.filter((item) => missingByFile[item.filename]);
  }, [normalizedItems, missingByFile]);

  // Hide checklist while availability is loading, and hide permanently when all files exist.
  if (normalizedItems.length === 0 || !missingByFile || missingItems.length === 0) return null;

  return (
    <Alert className="border-amber-300 bg-amber-50 text-amber-950">
      <Camera className="h-4 w-4 text-amber-700" />
      <AlertTitle>Documentation assets pending</AlertTitle>
      <AlertDescription>
        <p className="mb-3 text-sm text-amber-900">
          Add files to <span className="font-mono">public/docs/</span>. Help pages render real images automatically when present.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {missingItems.map((item) => (
            <div key={item.filename} className="rounded-lg border border-amber-200 bg-white p-3">
              <p className="font-mono text-xs font-semibold text-amber-900">{item.filename}</p>
              <p className="mt-1 text-xs text-amber-900">{item.whereToCapture}</p>
              {item.usedIn ? <p className="mt-1 text-[11px] text-amber-700">Used in: {item.usedIn}</p> : null}
            </div>
          ))}
        </div>
      </AlertDescription>
    </Alert>
  );
}
