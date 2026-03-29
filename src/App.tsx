import React, { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { APP_PATHS } from "@/app/route-metadata";

import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";

import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import StepUpRecoveryDialog from "@/components/auth/StepUpRecoveryDialog";
import HelpAssistantWidget from "@/components/help/HelpAssistantWidget";
import { getRoleHelpHome } from "@/help/contextual-help";
import RouteMetricsTracker from "@/components/RouteMetricsTracker";
import { MutationEventBridge, queryClient } from "@/lib/query-client";

const Login = lazy(() => import("@/pages/Login"));
const AcceptInvite = lazy(() => import("@/pages/AcceptInvite"));
const VerifyEmail = lazy(() => import("@/pages/VerifyEmail"));
const ConnectorDownload = lazy(() => import("@/pages/ConnectorDownload"));
const PrinterSetup = lazy(() => import("@/pages/PrinterSetup"));
const ForgotPassword = lazy(() => import("@/pages/ForgotPassword"));
const ResetPassword = lazy(() => import("@/pages/ResetPassword"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Licensees = lazy(() => import("@/pages/Licensees"));
const QRRequests = lazy(() => import("@/pages/QRRequests"));
const Batches = lazy(() => import("@/pages/Batches"));
const QRTracking = lazy(() => import("@/pages/QRTracking"));
const Manufacturers = lazy(() => import("@/pages/Manufacturers"));
const AuditLogs = lazy(() => import("@/pages/AuditLogs"));
const Incidents = lazy(() => import("@/pages/Incidents"));
const IR = lazy(() => import("@/pages/IR"));
const IRIncidentDetail = lazy(() => import("@/pages/IRIncidentDetail"));
const SupportCenter = lazy(() => import("@/pages/SupportCenter"));
const Governance = lazy(() => import("@/pages/Governance"));
const Verify = lazy(() => import("@/pages/Verify"));
const VerifyLanding = lazy(() => import("@/pages/VerifyLanding"));
const Index = lazy(() => import("@/pages/Index"));
const NotFound = lazy(() => import("@/pages/NotFound"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const AccountSettings = lazy(() => import("@/pages/AccountSettings"));
const HelpHub = lazy(() => import("@/pages/help/HelpHub"));
const HelpAuthOverview = lazy(() => import("@/pages/help/AuthOverview"));
const HelpGettingAccess = lazy(() => import("@/pages/help/GettingAccess"));
const HelpSettingPassword = lazy(() => import("@/pages/help/SettingPassword"));
const HelpRolesPermissions = lazy(() => import("@/pages/help/RolesPermissions"));
const HelpSuperAdmin = lazy(() => import("@/pages/help/SuperAdmin"));
const HelpLicenseeAdmin = lazy(() => import("@/pages/help/LicenseeAdmin"));
const HelpManufacturer = lazy(() => import("@/pages/help/Manufacturer"));
const HelpCustomer = lazy(() => import("@/pages/help/Customer"));
const HelpIncidentResponse = lazy(() => import("@/pages/help/IncidentResponse"));
const HelpPolicyAlerts = lazy(() => import("@/pages/help/PolicyAlerts"));
const HelpIncidentActions = lazy(() => import("@/pages/help/IncidentActions"));
const HelpCommunications = lazy(() => import("@/pages/help/Communications"));
const HelpSupport = lazy(() => import("@/pages/help/Support"));
const HelpGovernance = lazy(() => import("@/pages/help/Governance"));
const HelpIncidents = lazy(() => import("@/pages/help/Incidents"));

function RedirectWithQuery({ to }: { to: string }) {
  const location = useLocation();
  return <Navigate to={`${to}${location.search}`} replace />;
}

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
  allowedRawRoles,
}: {
  children: React.ReactNode;
  allowedRoles?: string[];
  allowedRawRoles?: string[];
}) {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />;
  }

  if (allowedRawRoles && user) {
    const rawRole = String(user.rawRole || "").trim().toUpperCase();
    if (!allowedRawRoles.includes(rawRole)) {
      return <Navigate to="/dashboard" replace />;
    }
  }

  return <>{children}</>;
}

function AuthRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  return <>{children}</>;
}

function HelpRoleRoute({
  children,
  allowedRoles,
  allowPublic = true,
}: {
  children: React.ReactNode;
  allowedRoles?: string[];
  allowPublic?: boolean;
}) {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <LoadingScreen />;

  if (!isAuthenticated) {
    if (allowPublic) return <>{children}</>;
    return <Navigate to="/help/customer" replace />;
  }

  if (user?.role === "super_admin") return <>{children}</>;

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to={getRoleHelpHome(user.role)} replace />;
  }

  return <>{children}</>;
}

/* =========================
   Routes
========================= */
function AppRoutes() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        {/* Public */}
        <Route path="/" element={<Index />} />
        <Route path="/verify" element={<VerifyLanding />} />
        <Route path="/verify/:code" element={<Verify />} />
        <Route path="/scan" element={<Verify />} />
        <Route path="/connector-download" element={<ConnectorDownload />} />
        <Route path="/help" element={<HelpHub />} />
        <Route
          path="/help/auth-overview"
          element={
            <HelpRoleRoute>
              <HelpAuthOverview />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/getting-access"
          element={
            <HelpRoleRoute>
              <HelpGettingAccess />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/setting-password"
          element={
            <HelpRoleRoute>
              <HelpSettingPassword />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/roles-permissions"
          element={
            <HelpRoleRoute>
              <HelpRolesPermissions />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/super-admin"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpSuperAdmin />
            </HelpRoleRoute>
          }
        />
        <Route path="/help/superadmin" element={<Navigate to="/help/super-admin" replace />} />
        <Route
          path="/help/licensee-admin"
          element={
            <HelpRoleRoute allowedRoles={["licensee_admin"]} allowPublic={false}>
              <HelpLicenseeAdmin />
            </HelpRoleRoute>
          }
        />
        <Route path="/help/licensee" element={<Navigate to="/help/licensee-admin" replace />} />
        <Route
          path="/help/manufacturer"
          element={
            <HelpRoleRoute allowedRoles={["manufacturer"]} allowPublic={true}>
              <HelpManufacturer />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/customer"
          element={
            <HelpRoleRoute allowPublic={true}>
              <HelpCustomer />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/incident-response"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpIncidentResponse />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/policy-alerts"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpPolicyAlerts />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/incident-actions"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpIncidentActions />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/communications"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpCommunications />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/support"
          element={
            <HelpRoleRoute allowPublic={true}>
              <HelpSupport />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/governance"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpGovernance />
            </HelpRoleRoute>
          }
        />
        <Route
          path="/help/incidents"
          element={
            <HelpRoleRoute allowedRoles={["super_admin"]} allowPublic={false}>
              <HelpIncidents />
            </HelpRoleRoute>
          }
        />

        {/* Auth */}
        <Route
          path="/login"
          element={
            <AuthRoute>
              <Login />
            </AuthRoute>
          }
        />
        <Route
          path="/accept-invite"
          element={
            <AuthRoute>
              <AcceptInvite />
            </AuthRoute>
          }
        />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route
          path="/forgot-password"
          element={
            <AuthRoute>
              <ForgotPassword />
            </AuthRoute>
          }
        />
        <Route
          path="/reset-password"
          element={
            <AuthRoute>
              <ResetPassword />
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
            <ProtectedRoute>
              <RedirectWithQuery to={APP_PATHS.scanActivity} />
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
          path={APP_PATHS.printerSetup}
          element={
            <ProtectedRoute allowedRoles={["manufacturer"]}>
              <PrinterSetup />
            </ProtectedRoute>
          }
        />

        <Route
          path={APP_PATHS.codeRequests}
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
              <QRRequests />
            </ProtectedRoute>
          }
        />
        <Route
          path="/qr-requests"
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin"]}>
              <RedirectWithQuery to={APP_PATHS.codeRequests} />
            </ProtectedRoute>
          }
        />

        <Route path="/product-batches" element={<Navigate to="/batches" replace />} />

        <Route
          path={APP_PATHS.scanActivity}
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
              <QRTracking />
            </ProtectedRoute>
          }
        />
        <Route
          path="/qr-tracking"
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
              <RedirectWithQuery to={APP_PATHS.scanActivity} />
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
          path={APP_PATHS.auditHistory}
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
              <AuditLogs />
            </ProtectedRoute>
          }
        />
        <Route
          path="/audit-logs"
          element={
            <ProtectedRoute allowedRoles={["super_admin", "licensee_admin", "manufacturer"]}>
              <RedirectWithQuery to={APP_PATHS.auditHistory} />
            </ProtectedRoute>
          }
        />

        <Route
          path={APP_PATHS.incidentResponse}
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <IR />
            </ProtectedRoute>
          }
        />
        <Route
          path="/ir"
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <RedirectWithQuery to={APP_PATHS.incidentResponse} />
            </ProtectedRoute>
          }
        />
        <Route
          path="/incidents"
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <RedirectWithQuery to={APP_PATHS.incidentResponse} />
            </ProtectedRoute>
          }
        />

        <Route
          path="/support"
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <SupportCenter />
            </ProtectedRoute>
          }
        />

        <Route
          path="/governance"
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <Governance />
            </ProtectedRoute>
          }
        />

        <Route
          path={`${APP_PATHS.incidentDetailPrefix}/:id`}
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <IRIncidentDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/ir/incidents/:id"
          element={
            <ProtectedRoute allowedRoles={["super_admin"]}>
              <IRIncidentDetail />
            </ProtectedRoute>
          }
        />

        <Route
          path={APP_PATHS.settings}
          element={
            <ProtectedRoute>
              <SettingsPage />
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
      <MutationEventBridge />
      <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <StepUpRecoveryDialog />
          <BrowserRouter
            future={{
              v7_startTransition: true,
              v7_relativeSplatPath: true,
            }}
          >
            <AppRoutes />
            <RouteMetricsTracker />
            <HelpAssistantWidget />
          </BrowserRouter>
        </TooltipProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}
