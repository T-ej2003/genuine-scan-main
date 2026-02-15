import React from "react";
import { Link } from "react-router-dom";
import { ArrowRight, BookOpenCheck, Camera, FileImage, Shield } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  HELP_INTRO_SLUGS,
  HELP_ROLE_SLUGS,
  getHelpDoc,
  getScreenshotRequirements,
} from "@/lib/help-docs";

export default function Help() {
  const introPages = HELP_INTRO_SLUGS.map((slug) => getHelpDoc(slug)).filter(Boolean);
  const rolePages = HELP_ROLE_SLUGS.map((slug) => getHelpDoc(slug)).filter(Boolean);
  const screenshots = getScreenshotRequirements();

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card/70">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Help & Documentation</h1>
              <p className="text-sm text-muted-foreground">
                Role-based product guides with screenshot checklist and capture plan.
              </p>
            </div>
          </div>
          <Button asChild variant="outline">
            <Link to="/verify">Go to Verify</Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl space-y-8 px-4 py-6 md:py-8">
        <Alert className="border-sky-200 bg-sky-50 text-sky-900">
          <BookOpenCheck className="h-4 w-4 text-sky-700" />
          <AlertTitle>Read these two pages first</AlertTitle>
          <AlertDescription>
            Start with <strong>Getting Access</strong> and <strong>Setting Your Password</strong>. They explain
            role-specific onboarding before task guides.
          </AlertDescription>
        </Alert>

        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Intro Pages</h2>
            <Badge variant="secondary">Start here</Badge>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            {introPages.map((doc) => (
              <Card key={doc!.slug}>
                <CardHeader>
                  <CardTitle>{doc!.title}</CardTitle>
                  <CardDescription>{doc!.summary}</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button asChild>
                    <Link to={`/help/${doc!.slug}`}>
                      Open page
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Link>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section className="space-y-4">
          <h2 className="text-xl font-semibold">Role Sections</h2>
          <div className="grid gap-4 md:grid-cols-2">
            {rolePages.map((doc) => (
              <Card key={doc!.slug} className="h-full">
                <CardHeader>
                  <CardTitle>{doc!.title}</CardTitle>
                  <CardDescription>{doc!.summary}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-2">
                    {doc!.canDo.slice(0, 3).map((item) => (
                      <p key={item} className="text-sm text-slate-600">
                        • {item}
                      </p>
                    ))}
                  </div>
                  <Button asChild variant="outline">
                    <Link to={`/help/${doc!.slug}`}>
                      Open {doc!.title}
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Link>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Screenshots Needed</h2>
            <Badge variant="outline">/public/docs</Badge>
          </div>

          <Alert className="border-amber-200 bg-amber-50 text-amber-900">
            <Camera className="h-4 w-4 text-amber-700" />
            <AlertTitle>Capture checklist</AlertTitle>
            <AlertDescription>
              Add each file below to <code>/public/docs/</code>. Role pages automatically render real images if
              present, otherwise they show placeholders.
            </AlertDescription>
          </Alert>

          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-border text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="px-4 py-3 text-left font-semibold text-slate-700">Filename</th>
                      <th className="px-4 py-3 text-left font-semibold text-slate-700">Where to capture</th>
                      <th className="px-4 py-3 text-left font-semibold text-slate-700">Used in pages</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {screenshots.map((shot) => (
                      <tr key={shot.file}>
                        <td className="px-4 py-3 align-top font-mono text-xs text-slate-800">
                          <div className="flex items-start gap-2">
                            <FileImage className="mt-0.5 h-4 w-4 text-slate-500" />
                            {shot.file}
                          </div>
                        </td>
                        <td className="px-4 py-3 align-top text-slate-700">{shot.capture}</td>
                        <td className="px-4 py-3 align-top text-slate-600">{shot.pages.join(", ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </section>
      </main>
    </div>
  );
}
