import React, { useMemo, useState } from "react";
import { ExternalLink, ImageOff } from "lucide-react";
import { cn } from "@/lib/utils";

type Props = {
  filename: string;
  alt: string;
  caption?: string;
  className?: string;
  eager?: boolean;
};

export function DocScreenshot({ filename, alt, caption, className, eager }: Props) {
  const [missing, setMissing] = useState(false);

  const src = useMemo(() => `/docs/${filename}`.replace(/\/{2,}/g, "/"), [filename]);

  return (
    <figure className={cn("space-y-2", className)}>
      <div className="overflow-hidden rounded-xl border bg-white shadow-sm">
        {missing ? (
          <div className="flex min-h-[180px] flex-col items-center justify-center gap-2 bg-muted/40 px-4 py-10 text-center">
            <ImageOff className="h-6 w-6 text-muted-foreground" />
            <p className="text-sm font-medium text-foreground">Screenshot missing</p>
            <p className="text-xs text-muted-foreground">
              Add <span className="font-mono">{filename}</span> to <span className="font-mono">public/docs/</span>
            </p>
          </div>
        ) : (
          <img
            src={src}
            alt={alt}
            loading={eager ? "eager" : "lazy"}
            className="block w-full bg-white"
            onError={() => setMissing(true)}
          />
        )}
      </div>

      <figcaption className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>{caption || alt}</span>
        {!missing ? (
          <a
            href={src}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            Open <ExternalLink className="h-3.5 w-3.5" />
          </a>
        ) : null}
      </figcaption>
    </figure>
  );
}

