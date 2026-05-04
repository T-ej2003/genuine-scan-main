import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import { cleanupDangerousLegacyBrowserStorage } from "@/lib/browser-storage-cleanup";
import { cleanupNonEssentialBrowserState } from "@/lib/consent";
import { initFrontendMonitoring } from "@/lib/observability/frontend-monitoring";

cleanupDangerousLegacyBrowserStorage();
cleanupNonEssentialBrowserState();
initFrontendMonitoring();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider attribute="class" defaultTheme="light" enableSystem disableTransitionOnChange>
      <App />
    </ThemeProvider>
  </React.StrictMode>
);
