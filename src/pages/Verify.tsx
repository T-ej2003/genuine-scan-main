import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { mockLicensees, mockManufacturers } from '@/lib/mock-data';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Shield, CheckCircle, XCircle, ExternalLink, MapPin, Building2, Loader2 } from 'lucide-react';

interface VerificationResult {
  isValid: boolean;
  licensee?: {
    name: string;
    location: string;
    website?: string;
  };
  manufacturer?: {
    name: string;
    location: string;
  };
  qrCode?: string;
}

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<VerificationResult | null>(null);

  useEffect(() => {
    // Simulate verification API call
    const timer = setTimeout(() => {
      if (!code) {
        setResult({ isValid: false });
        setIsLoading(false);
        return;
      }

      // Extract prefix from QR code (e.g., "A" from "A0000000001")
      const prefix = code.replace(/[0-9]/g, '');
      const licensee = mockLicensees.find(l => l.prefix === prefix);

      if (licensee) {
        // Pick a random manufacturer for demo
        const manufacturer = mockManufacturers.find(m => m.licenseeId === licensee.id);
        
        setResult({
          isValid: true,
          licensee: {
            name: licensee.name,
            location: licensee.location,
            website: licensee.website,
          },
          manufacturer: manufacturer ? {
            name: manufacturer.name,
            location: manufacturer.location,
          } : undefined,
          qrCode: code,
        });
      } else {
        setResult({ isValid: false, qrCode: code });
      }
      
      setIsLoading(false);
    }, 1500);

    return () => clearTimeout(timer);
  }, [code]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-secondary via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-white mb-4">
            <Shield className="h-10 w-10 text-primary" />
            <span className="text-2xl font-bold">AuthenticQR</span>
          </Link>
          <p className="text-slate-400">Product Verification</p>
        </div>

        <Card className="border-0 shadow-2xl overflow-hidden animate-fade-in">
          {isLoading ? (
            <CardContent className="py-16 text-center">
              <Loader2 className="h-12 w-12 animate-spin text-primary mx-auto mb-4" />
              <p className="text-lg font-medium">Verifying authenticity...</p>
              <p className="text-sm text-muted-foreground mt-1">Please wait</p>
            </CardContent>
          ) : result?.isValid ? (
            <>
              {/* Success header */}
              <div className="bg-primary p-6 text-center">
                <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-white/20 mb-4">
                  <CheckCircle className="h-10 w-10 text-white" />
                </div>
                <h1 className="text-2xl font-bold text-white">Genuine Product</h1>
                <p className="text-primary-foreground/80 mt-1">This is an authentic item</p>
              </div>
              
              <CardContent className="p-6 space-y-6">
                {/* QR Code */}
                <div className="text-center p-4 bg-muted rounded-lg">
                  <p className="text-sm text-muted-foreground mb-1">Verified Code</p>
                  <p className="font-mono text-lg font-bold">{result.qrCode}</p>
                </div>

                {/* Licensee Info */}
                <div className="space-y-4">
                  <div className="flex items-start gap-4">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      <Building2 className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Licensed By</p>
                      <p className="font-semibold">{result.licensee?.name}</p>
                    </div>
                  </div>

                  <div className="flex items-start gap-4">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      <MapPin className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Manufactured In</p>
                      <p className="font-semibold">
                        {result.manufacturer?.location || result.licensee?.location}
                      </p>
                    </div>
                  </div>
                </div>

                {/* CTA */}
                {result.licensee?.website && (
                  <Button asChild className="w-full" size="lg">
                    <a href={result.licensee.website} target="_blank" rel="noopener noreferrer">
                      Visit Official Website
                      <ExternalLink className="ml-2 h-4 w-4" />
                    </a>
                  </Button>
                )}
              </CardContent>
            </>
          ) : (
            <>
              {/* Error header */}
              <div className="bg-destructive p-6 text-center">
                <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-white/20 mb-4">
                  <XCircle className="h-10 w-10 text-white" />
                </div>
                <h1 className="text-2xl font-bold text-white">Verification Failed</h1>
                <p className="text-destructive-foreground/80 mt-1">This code could not be verified</p>
              </div>
              
              <CardContent className="p-6 space-y-6 text-center">
                {result?.qrCode && (
                  <div className="p-4 bg-muted rounded-lg">
                    <p className="text-sm text-muted-foreground mb-1">Scanned Code</p>
                    <p className="font-mono text-lg font-bold">{result.qrCode}</p>
                  </div>
                )}

                <div className="space-y-2">
                  <p className="font-medium">This product may be counterfeit</p>
                  <p className="text-sm text-muted-foreground">
                    The QR code you scanned is not registered in our system. 
                    Please verify that you purchased this product from an authorized retailer.
                  </p>
                </div>

                <Button variant="outline" asChild className="w-full">
                  <Link to="/">Return to Home</Link>
                </Button>
              </CardContent>
            </>
          )}
        </Card>

        <p className="text-center text-slate-500 text-sm mt-6">
          Powered by AuthenticQR Platform
        </p>
      </div>
    </div>
  );
}
