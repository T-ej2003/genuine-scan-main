import { Link, type LinkProps } from "react-router";

import { MscqrLogo } from "@/components/brand/MscqrLogo";
import { cn } from "@/lib/utils";

type BrandLockupProps = {
  to?: LinkProps["to"];
  className?: string;
  markClassName?: string;
  iconClassName?: string;
  textClassName?: string;
  wordmarkClassName?: string;
  ariaLabel?: string;
  onClick?: LinkProps["onClick"];
};

export function BrandLockup({
  to,
  className,
  markClassName,
  iconClassName,
  textClassName,
  wordmarkClassName,
  ariaLabel = "MSCQR",
  onClick,
}: BrandLockupProps) {
  const content = (
    <>
      <span
        className={cn(
          "flex shrink-0 items-center justify-center overflow-hidden rounded-2xl border border-moonlight-300 bg-moonlight-100",
          markClassName,
        )}
      >
        <MscqrLogo variant="mark" decorative className={cn("size-7", iconClassName)} />
      </span>
      <MscqrLogo
        variant="wordmark"
        decorative
        className={cn("h-5 w-auto min-w-0 max-w-[7.5rem]", textClassName, wordmarkClassName)}
      />
    </>
  );

  if (to) {
    return (
      <Link to={to} className={cn("flex min-w-0 items-center", className)} aria-label={ariaLabel} onClick={onClick}>
        {content}
      </Link>
    );
  }

  return (
    <div className={cn("flex min-w-0 items-center", className)} aria-label={ariaLabel} role="img">
      {content}
    </div>
  );
}
