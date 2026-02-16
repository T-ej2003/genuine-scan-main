import React, { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { getContextualHelpRoute } from "@/help/contextual-help";
import {
  LayoutDashboard,
  Building2,
  QrCode,
  Factory,
  FileText,
  Settings,
  LogOut,
  Menu,
  ChevronDown,
  Shield,
  ScanEye,
  ShieldAlert,
  CircleHelp,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  roles: string[];
}

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Licensees", href: "/licensees", icon: Building2, roles: ["super_admin"] },
  { label: "QR Codes", href: "/qr-codes", icon: QrCode, roles: ["super_admin"] },
  { label: "QR Requests", href: "/qr-requests", icon: FileText, roles: ["super_admin", "licensee_admin"] },
  { label: "Batches", href: "/batches", icon: FileText, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Manufacturers", href: "/manufacturers", icon: Factory, roles: ["super_admin", "licensee_admin"] },
  { label: "QR Tracking", href: "/qr-tracking", icon: ScanEye, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "IR Center", href: "/ir", icon: Shield, roles: ["super_admin"] },
  { label: "Incidents", href: "/incidents", icon: ShieldAlert, roles: ["super_admin"] },
  { label: "Audit Logs", href: "/audit-logs", icon: FileText, roles: ["super_admin", "licensee_admin"] },
];

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const filteredNavItems = navItems.filter((item) => user && item.roles.includes(user.role));
  const contextualHelpRoute = getContextualHelpRoute(location.pathname, user?.role);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const getRoleLabel = (role?: string) => {
    if (!role) return "User";
    switch (role) {
      case "super_admin":
        return "Super Admin";
      case "licensee_admin":
        return "Licensee Admin";
      case "manufacturer":
        return "Manufacturer";
      default:
        return role;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 z-50 h-full w-64 bg-sidebar text-sidebar-foreground transform transition-transform duration-200 ease-in-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center gap-2 px-6 border-b border-sidebar-border">
            <Shield className="h-8 w-8 text-sidebar-primary" />
            <span className="font-bold text-lg">AuthenticQR</span>
          </div>

          <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
            {filteredNavItems.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors",
                    isActive
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  )}
                >
                  <item.icon className="h-5 w-5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="border-t border-sidebar-border p-4">
            <div className="flex items-center gap-3 px-2 py-2">
              <div className="h-10 w-10 rounded-full bg-sidebar-accent flex items-center justify-center">
                <span className="text-sm font-semibold text-sidebar-accent-foreground">
                  {user?.name?.charAt(0) || "U"}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || "User"}</p>
                <p className="text-xs text-sidebar-foreground/60 truncate">{getRoleLabel(user?.role)}</p>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 h-16 bg-card border-b border-border flex items-center justify-between px-4 lg:px-6">
          <button
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden p-2 rounded-md hover:bg-muted"
            aria-label="Open sidebar"
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex-1" />

          <Button asChild variant="ghost" className="mr-1 gap-2">
            <Link to={contextualHelpRoute}>
              <CircleHelp className="h-4 w-4 text-muted-foreground" />
              <span className="hidden sm:inline">Help</span>
            </Link>
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2">
                <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                  <span className="text-sm font-semibold text-primary">
                    {user?.name?.charAt(0) || "U"}
                  </span>
                </div>
                <span className="hidden sm:inline">{user?.name || "User"}</span>
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </Button>
            </DropdownMenuTrigger>

            <DropdownMenuContent align="end" className="w-56">
              <div className="px-3 py-2">
                <p className="text-sm font-medium">{user?.name}</p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>

              <DropdownMenuSeparator />

              <DropdownMenuItem onClick={() => navigate("/account")}>
                <Settings className="mr-2 h-4 w-4" />
                Account
              </DropdownMenuItem>

              <DropdownMenuSeparator />

              <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </header>

        <main className="p-4 lg:p-6">{children}</main>
        <footer className="px-4 pb-6 lg:px-6">
          <div className="text-center text-xs text-muted-foreground">
            Need guidance on this page?{" "}
            <Link to={contextualHelpRoute} className="text-foreground underline-offset-4 hover:underline">
              Open the relevant help section
            </Link>
            .
          </div>
        </footer>
      </div>
    </div>
  );
}
