import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

export default {
  darkMode: ["class"],
  content: ["./pages/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./app/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
        success: {
          DEFAULT: "hsl(var(--success))",
          foreground: "hsl(var(--success-foreground))",
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          foreground: "hsl(var(--warning-foreground))",
        },
        info: {
          DEFAULT: "hsl(var(--info))",
          foreground: "hsl(var(--info-foreground))",
        },
        moonlight: {
          50: "#FAFAFF",
          100: "#F4F2FF",
          200: "#E6E6FF",
          300: "#CCCCFF",
          400: "#A3A3CC",
          700: "#5C5C99",
          900: "#292966",
        },
        mscqr: {
          background: "hsl(var(--mscqr-background))",
          "background-soft": "hsl(var(--mscqr-background-soft))",
          surface: "hsl(var(--mscqr-surface))",
          "surface-elevated": "hsl(var(--mscqr-surface-elevated))",
          "surface-muted": "hsl(var(--mscqr-surface-muted))",
          border: "hsl(var(--mscqr-border))",
          "border-strong": "hsl(var(--mscqr-border-strong))",
          primary: "hsl(var(--mscqr-text-primary))",
          secondary: "hsl(var(--mscqr-text-secondary))",
          muted: "hsl(var(--mscqr-text-muted))",
          accent: "hsl(var(--mscqr-accent))",
          "accent-soft": "hsl(var(--mscqr-accent-soft))",
          verified: "hsl(var(--mscqr-verified))",
          issued: "hsl(var(--mscqr-issued))",
          pending: "hsl(var(--mscqr-print-pending))",
          confirmed: "hsl(var(--mscqr-print-confirmed))",
          review: "hsl(var(--mscqr-review-required))",
          duplicate: "hsl(var(--mscqr-duplicate-detected))",
          blocked: "hsl(var(--mscqr-blocked))",
          replaced: "hsl(var(--mscqr-replaced))",
          expired: "hsl(var(--mscqr-expired))",
          degraded: "hsl(var(--mscqr-degraded))",
          support: "hsl(var(--mscqr-support-open))",
          audit: "hsl(var(--mscqr-audit-exported))",
          risk: {
            low: "hsl(var(--mscqr-risk-low))",
            watch: "hsl(var(--mscqr-risk-watch))",
            elevated: "hsl(var(--mscqr-risk-elevated))",
            high: "hsl(var(--mscqr-risk-high))",
            blocked: "hsl(var(--mscqr-risk-blocked))",
          },
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in": {
          from: { opacity: "0", transform: "translateX(-10px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "fade-in": "fade-in 0.3s ease-out",
        "slide-in": "slide-in 0.3s ease-out",
      },
    },
  },
  plugins: [tailwindcssAnimate],
} satisfies Config;
