import React, { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

import { AuthProvider, useAuth } from "@/contexts/AuthContext";

const Login = lazy(() => import("@/pages/Login"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Licensees = lazy(() => import("@/pages/Licensees"));
const QRCodes = lazy(() => import("@/pages/QRCodes"));
const QRRequests = lazy(() => import("@/pages/QRRequests"));
const Batches = lazy(() => import("@/pages/Batches"));
const QRTracking = lazy(() => import("@/pages/QRTracking"));
const Manufacturers = lazy(() => import("@/pages/Manufacturers"));
const AuditLogs = lazy(() => import("@/pages/AuditLogs"));
const Verify = lazy(() => import("@/pages/Verify"));
const VerifyLanding = lazy(() => import("@/pages/VerifyLanding"));
const NotFound = lazy(() => import("@/pages/NotFound"));
const AccountSettings = lazy(() => import("@/pages/AccountSettings"));

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

function RootRoute() {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return <LoadingScreen />;
  return <Navigate to={isAuthenticated ? "/dashboard" : "/verify"} replace />;
}

/* =========================
   Routes
========================= */
function AppRoutes() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        {/* Public */}
        <Route path="/" element={<RootRoute />} />
        <Route path="/verify" element={<VerifyLanding />} />
        <Route path="/verify/:code" element={<Verify />} />
        <Route path="/scan" element={<Verify />} />

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
            <ProtectedRoute allowedRoles={["super_admin"]}>
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
          path="/qr-requests"
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
              <QRRequests />
            </ProtectedRoute>
          }
        />

        <Route path="/product-batches" element={<Navigate to="/batches" replace />} />

        <Route
          path="/qr-tracking"
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
              <QRTracking />
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
    </Suspense>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter
            future={{
              v7_startTransition: true,
              v7_relativeSplatPath: true,
            }}
          >
            <AppRoutes />
          </BrowserRouter>
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}
