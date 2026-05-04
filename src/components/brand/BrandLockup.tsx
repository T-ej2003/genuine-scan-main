import { Link, type LinkProps } from "react-router-dom";

import { cn } from "@/lib/utils";

type BrandLockupProps = {
  to?: LinkProps["to"];
  className?: string;
  markClassName?: string;
  iconClassName?: string;
  textClassName?: string;
  ariaLabel?: string;
  onClick?: LinkProps["onClick"];
};

export function BrandLockup({
  to,
  className,
  markClassName,
  iconClassName,
  textClassName,
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
        <img src="/brand/mscqr-mark.svg" alt="" className={cn("size-7", iconClassName)} aria-hidden="true" />
      </span>
      <span className={cn("min-w-0 font-semibold tracking-tight", textClassName)}>MSCQR</span>
    </>
  );

  if (to) {
    return (
      <Link to={to} className={cn("flex min-w-0 items-center", className)} aria-label={ariaLabel} onClick={onClick}>
        {content}
      </Link>
    );
  }

  return <div className={cn("flex min-w-0 items-center", className)}>{content}</div>;
}
