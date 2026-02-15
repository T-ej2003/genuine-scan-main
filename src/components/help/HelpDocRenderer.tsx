import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ChevronLeft, Lightbulb, ShieldCheck, Wrench } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import type { HelpDoc } from "@/lib/help-docs";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotsChecklist } from "@/components/help/ScreenshotsChecklist";

export function HelpDocRenderer({ doc }: { doc: HelpDoc }) {
  const screenshots = useMemo(
    () => doc.steps.flatMap((step) => step.screenshots),
    [doc.steps]
  );

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card/70">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Help & Documentation</p>
            <h1 className="text-2xl font-bold text-foreground">{doc.title}</h1>
          </div>
          <Button variant="outline" asChild>
            <Link to="/help">
              <ChevronLeft className="mr-2 h-4 w-4" />
              All Help Pages
            </Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl space-y-6 px-4 py-6 md:py-8">
        <Card>
          <CardHeader className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{doc.isIntro ? "Intro" : "Role Guide"}</Badge>
              {doc.roleHeading ? <Badge variant="outline">{doc.roleHeading}</Badge> : null}
            </div>
            <CardTitle>{doc.title}</CardTitle>
            <CardDescription>{doc.summary}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-5 md:grid-cols-2">
            <div>
              <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">What this page covers</h2>
              <ul className="space-y-2">
                {doc.canDo.map((item) => (
                  <li key={item} className="flex gap-2 text-sm text-slate-700">
                    <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-600" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {doc.cannotDo && doc.cannotDo.length > 0 ? (
              <div>
                <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">Limits to know</h2>
                <ul className="space-y-2">
                  {doc.cannotDo.map((item) => (
                    <li key={item} className="flex gap-2 text-sm text-slate-700">
                      <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-600" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </CardContent>
        </Card>

        <ScreenshotsChecklist screenshots={screenshots} />

        {doc.recommendedImprovements && doc.recommendedImprovements.length > 0 ? (
          <Alert className="border-amber-200 bg-amber-50 text-amber-900">
            <Lightbulb className="h-4 w-4 text-amber-700" />
            <AlertTitle>Recommended Improvement</AlertTitle>
            <AlertDescription>
              <ul className="mt-2 space-y-1 text-sm">
                {doc.recommendedImprovements.map((item) => (
                  <li key={item}>• {item}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <h2 className="text-xl font-semibold">Step-by-step</h2>
          <div className="space-y-4">
            {doc.steps.map((step, idx) => (
              <Card key={step.title}>
                <CardHeader>
                  <CardDescription>Step {idx + 1}</CardDescription>
                  <CardTitle className="text-lg">{step.title}</CardTitle>
                  <CardDescription>{step.summary}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <ol className="space-y-2 pl-5 text-sm text-slate-700">
                    {step.bullets.map((bullet) => (
                      <li key={bullet} className="list-decimal">
                        {bullet}
                      </li>
                    ))}
                  </ol>

                  {step.screenshots.length > 0 ? (
                    <div className="grid gap-4 lg:grid-cols-2">
                      {step.screenshots.map((shot) => (
                        <DocScreenshot key={`${step.title}-${shot.file}`} screenshot={shot} />
                      ))}
                    </div>
                  ) : null}
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Wrench className="h-4 w-4" />
                Troubleshooting
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Accordion type="single" collapsible className="w-full">
                {doc.troubleshooting.map((item, idx) => (
                  <AccordionItem value={`issue-${idx}`} key={item.question}>
                    <AccordionTrigger>{item.question}</AccordionTrigger>
                    <AccordionContent>{item.answer}</AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">FAQ</CardTitle>
            </CardHeader>
            <CardContent>
              <Accordion type="single" collapsible className="w-full">
                {doc.faqs.map((item, idx) => (
                  <AccordionItem value={`faq-${idx}`} key={item.question}>
                    <AccordionTrigger>{item.question}</AccordionTrigger>
                    <AccordionContent>{item.answer}</AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </CardContent>
          </Card>
        </section>
      </main>
    </div>
  );
}
