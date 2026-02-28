import { cn } from "@/lib/utils";

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "premium-shimmer rounded-md bg-[#bccad6]/45 motion-reduce:animate-none",
        className
      )}
      {...props}
    />
  );
}

export { Skeleton };
