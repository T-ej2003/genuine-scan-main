import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { QrCode } from "lucide-react";

export default function VerifyLanding() {
  const [code, setCode] = useState("");
  const navigate = useNavigate();

  const cleaned = useMemo(() => code.trim(), [code]);

  const go = () => {
    if (!cleaned) return;
    navigate(`/verify/${encodeURIComponent(cleaned)}`);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <QrCode className="h-5 w-5" /> Verify a Product
          </CardTitle>
          <CardDescription>Paste a QR code value (or scan to open the verify URL directly).</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="e.g. A0000000001"
            onKeyDown={(e) => {
              if (e.key === "Enter") go();
            }}
          />
          <Button className="w-full" onClick={go} disabled={!cleaned}>
            Verify
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

