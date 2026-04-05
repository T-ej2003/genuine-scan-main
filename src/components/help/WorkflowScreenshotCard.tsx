import React from "react";

import { DocScreenshot } from "@/components/help/DocScreenshot";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type WorkflowScreenshotCardProps = {
  title: string;
  description: string;
  filename: string;
  alt: string;
  caption: string;
  highlights: string[];
  eager?: boolean;
};

export function WorkflowScreenshotCard({
  title,
  description,
  filename,
  alt,
  caption,
  highlights,
  eager,
}: WorkflowScreenshotCardProps) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="space-y-2">
        <CardTitle className="text-base">{title}</CardTitle>
        <p className="text-sm text-muted-foreground">{description}</p>
      </CardHeader>
      <CardContent className="space-y-4">
        <DocScreenshot filename={filename} alt={alt} caption={caption} eager={eager} />
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">What to look for</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {highlights.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
