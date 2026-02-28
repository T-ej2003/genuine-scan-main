import React from "react";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { cn } from "@/lib/utils";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

export type PremiumAccordionItemConfig = {
  value: string;
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  content: React.ReactNode;
};

type PremiumSectionAccordionProps = {
  items: PremiumAccordionItemConfig[];
  defaultOpen?: string[];
  className?: string;
};

export function PremiumSectionAccordion({ items, defaultOpen, className }: PremiumSectionAccordionProps) {
  return (
    <Accordion
      type="multiple"
      defaultValue={defaultOpen}
      className={cn("space-y-3", className)}
    >
      {items.map((item) => (
        <AccordionItem
          key={item.value}
          value={item.value}
          className="overflow-hidden rounded-2xl border bg-white/90 shadow-[0_10px_22px_rgba(102,114,146,0.12)]"
          style={{ borderColor: `${PREMIUM_PALETTE.steel}66` }}
        >
          <AccordionTrigger className="px-4 py-3 hover:no-underline sm:px-5">
            <div className="flex w-full items-center justify-between gap-3 text-left">
              <div className="min-w-0">
                <p className="text-sm font-semibold tracking-[0.01em] text-[#4f5b75]">{item.title}</p>
                {item.subtitle ? <p className="mt-1 text-xs text-slate-500">{item.subtitle}</p> : null}
              </div>
              {item.badge ? <div className="shrink-0">{item.badge}</div> : null}
            </div>
          </AccordionTrigger>
          <AccordionContent className="px-4 pb-4 sm:px-5">{item.content}</AccordionContent>
        </AccordionItem>
      ))}
    </Accordion>
  );
}
