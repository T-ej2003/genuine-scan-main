import { Button } from "@/components/ui/button";
import { Shield, QrCode, Users, Factory, Smartphone, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

export default function Index() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-10 h-10 rounded-lg bg-primary flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold text-foreground">AuthenticQR</span>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/verify">
              <Button variant="ghost" size="sm">Verify Product</Button>
            </Link>
            <Link to="/login">
              <Button size="sm">Sign In</Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="py-20 lg:py-32">
        <div className="container mx-auto px-4 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary mb-6">
            <Shield className="w-4 h-4" />
            <span className="text-sm font-medium">Enterprise-Grade Authentication</span>
          </div>
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold text-foreground mb-6 leading-tight">
            Secure QR Authentication<br />
            <span className="text-primary">For Your Products</span>
          </h1>
          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10">
            Protect your brand with a multi-tenant QR verification platform.
            Track QR codes from allocation → printing → customer scans.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link to="/login">
              <Button size="lg" className="gap-2">
                Get Started <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link to="/verify">
              <Button size="lg" variant="outline" className="gap-2">
                <QrCode className="w-4 h-4" /> Verify a Product
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20 bg-muted/30">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">Everything You Need</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              End-to-end product authentication with strong tenant isolation.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <FeatureCard
              icon={Users}
              title="Multi-Tenant Isolation"
              description="Each licensee operates in an isolated workspace with its own QR pool."
            />
            <FeatureCard
              icon={QrCode}
              title="Real-Time Tracking"
              description="Track QR state from allocation to printing to customer verification scans."
            />
            <FeatureCard
              icon={Factory}
              title="Manufacturer Control"
              description="Assign and lock print confirmation to stop re-print/reuse of codes."
            />
            <FeatureCard
              icon={Smartphone}
              title="Instant Verification"
              description="Customers scan and verify authenticity instantly."
            />
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">How It Works</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              A simple flow from allocation to verification.
            </p>
          </div>

          <div className="grid md:grid-cols-4 gap-8">
            <StepCard number={1} title="Allocate QR Range" description="Super Admin allocates unique QR ranges per licensee." />
            <StepCard number={2} title="Create Batches" description="Licensee Admin splits QR pool into batches / product batches." />
            <StepCard number={3} title="Print & Lock" description="Manufacturer confirms printing; codes become locked." />
            <StepCard number={4} title="Verify & Trust" description="Customers scan codes to verify authenticity." />
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 bg-primary/5">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-4">Ready to Protect Your Brand?</h2>
          <p className="text-muted-foreground max-w-xl mx-auto mb-8">
            Secure your supply chain with AuthenticQR.
          </p>
          <Link to="/login">
            <Button size="lg" className="gap-2">
              Start Now <ArrowRight className="w-4 h-4" />
            </Button>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <Shield className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-semibold text-foreground">AuthenticQR</span>
          </div>
          <p className="text-sm text-muted-foreground">© 2026 AuthenticQR. All rights reserved.</p>
          <Link to="/login" className="text-sm text-primary hover:underline">
            Licensee Login
          </Link>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({
  icon: Icon,
  title,
  description,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
}) {
  return (
    <div className="p-6 rounded-xl bg-card border border-border hover:border-primary/50 transition-colors">
      <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
        <Icon className="w-6 h-6 text-primary" />
      </div>
      <h3 className="text-lg font-semibold text-foreground mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}

function StepCard({ number, title, description }: { number: number; title: string; description: string }) {
  return (
    <div className="text-center">
      <div className="w-12 h-12 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xl font-bold mx-auto mb-4">
        {number}
      </div>
      <h3 className="text-lg font-semibold text-foreground mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}

