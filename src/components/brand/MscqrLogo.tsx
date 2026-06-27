import type { ImgHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export type MscqrLogoVariant = "wordmark" | "mark" | "lockup";

const BRAND_ASSETS = {
  wordmark: "/brand/mscqr-wordmark.svg",
  mark: "/brand/mscqr-logo-mark.svg",
} as const;

type MscqrLogoProps = Omit<ImgHTMLAttributes<HTMLImageElement>, "src" | "alt"> & {
  variant?: MscqrLogoVariant;
  alt?: string;
  ariaLabel?: string;
  decorative?: boolean;
  markClassName?: string;
  wordmarkClassName?: string;
};

export function MscqrLogo({
  variant = "wordmark",
  alt,
  ariaLabel,
  decorative = false,
  className,
  markClassName,
  wordmarkClassName,
  loading = "eager",
  decoding = "async",
  ...imgProps
}: MscqrLogoProps) {
  const altText = decorative ? "" : alt || "MSCQR";

  if (variant === "lockup") {
    return (
      <span
        className={cn("inline-flex min-w-0 items-center gap-2", className)}
        aria-hidden={decorative ? "true" : undefined}
        aria-label={decorative ? undefined : ariaLabel || altText}
        role={decorative ? undefined : "img"}
      >
        <img
          src={BRAND_ASSETS.mark}
          alt=""
          aria-hidden="true"
          loading={loading}
          decoding={decoding}
          className={cn("size-8 shrink-0 object-contain", markClassName)}
        />
        <img
          src={BRAND_ASSETS.wordmark}
          alt=""
          aria-hidden="true"
          loading={loading}
          decoding={decoding}
          className={cn("h-5 w-auto min-w-0 object-contain", wordmarkClassName)}
        />
      </span>
    );
  }

  return (
    <img
      {...imgProps}
      src={BRAND_ASSETS[variant]}
      alt={altText}
      aria-hidden={decorative ? "true" : undefined}
      aria-label={decorative ? undefined : ariaLabel || altText}
      loading={loading}
      decoding={decoding}
      className={cn("block object-contain", className)}
    />
  );
}
