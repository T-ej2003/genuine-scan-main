import React from "react";
import { Link, useParams } from "react-router-dom";
import { AlertTriangle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { getHelpDoc } from "@/lib/help-docs";
import { HelpDocRenderer } from "@/components/help/HelpDocRenderer";

export default function HelpRole() {
  const { role } = useParams<{ role: string }>();
  const doc = getHelpDoc(role);

  if (!doc) {
    return (
      <div className="min-h-screen bg-background px-4 py-8">
        <div className="mx-auto w-full max-w-xl">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-amber-600" />
                Help page not found
              </CardTitle>
              <CardDescription>
                The documentation page <code>/help/{role}</code> does not exist.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Button asChild>
                <Link to="/help">Open Help Home</Link>
              </Button>
              <Button asChild variant="outline">
                <Link to="/help/customer">Open Customer Guide</Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return <HelpDocRenderer doc={doc} />;
}
