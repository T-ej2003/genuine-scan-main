import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

import { AuthProvider, useAuth } from "@/contexts/AuthContext";

import Index from "@/pages/Index";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Licensees from "@/pages/Licensees";
import QRCodes from "@/pages/QRCodes";
import Batches from "@/pages/Batches";
import ProductBatches from "@/pages/ProductBatches";
import Manufacturers from "@/pages/Manufacturers";
import AuditLogs from "@/pages/AuditLogs";
import Verify from "@/pages/Verify";
import VerifyLanding from "@/pages/VerifyLanding";
import NotFound from "@/pages/NotFound";
import AccountSettings from "@/pages/AccountSettings";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 0,
    },
  },
});

/* =========================
   Route Guards
========================= */
function LoadingScreen() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
    </div>
  );
}

function ProtectedRoute({
  children,
  allowedRoles,
}: {
  children: React.ReactNode;
  allowedRoles?: string[];
}) {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function AuthRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  return <>{children}</>;
}

/* =========================
   Routes
========================= */
function AppRoutes() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/" element={<Index />} />
      <Route path="/verify" element={<VerifyLanding />} />
      <Route path="/verify/:code" element={<Verify />} />

      {/* Auth */}
      <Route
        path="/login"
        element={
          <AuthRoute>
            <Login />
          </AuthRoute>
        }
      />

      {/* Protected */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />

      <Route
        path="/licensees"
        element={
          <ProtectedRoute allowedRoles={["super_admin"]}>
            <Licensees />
          </ProtectedRoute>
        }
      />

      <Route
        path="/qr-codes"
        element={
          <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
            <QRCodes />
          </ProtectedRoute>
        }
      />

      <Route
        path="/batches"
        element={
          <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
            <Batches />
          </ProtectedRoute>
        }
      />

      <Route
        path="/product-batches"
        element={
          <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
            <ProductBatches />
          </ProtectedRoute>
        }
      />

      <Route
        path="/manufacturers"
        element={
          <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
            <Manufacturers />
          </ProtectedRoute>
        }
      />

      <Route
        path="/audit-logs"
        element={
          <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
            <AuditLogs />
          </ProtectedRoute>
        }
      />

      <Route
        path="/account"
        element={
          <ProtectedRoute>
            <AccountSettings />
          </ProtectedRoute>
        }
      />

      {/* Catch-all */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

