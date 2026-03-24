import fs from "fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

const packageJson = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "package.json"), "utf8")
) as { name: string; version: string };

const gitSha =
  process.env.GIT_SHA ||
  process.env.GITHUB_SHA ||
  process.env.COMMIT_SHA ||
  process.env.RENDER_GIT_COMMIT ||
  process.env.VERCEL_GIT_COMMIT_SHA ||
  "unknown";
const shortGitSha = gitSha === "unknown" ? "unknown" : gitSha.slice(0, 12);
const releaseTag =
  shortGitSha === "unknown"
    ? `${packageJson.name}@${packageJson.version}`
    : `${packageJson.name}@${packageJson.version}+${shortGitSha}`;

// https://vitejs.dev/config/
export default defineConfig(() => ({
  server: {
    host: "::",
    port: 8080,
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY_TARGET || "http://localhost:4000",
        changeOrigin: true,
      },
    },
    hmr: {
      overlay: false,
    },
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  define: {
    __APP_NAME__: JSON.stringify(packageJson.name),
    __APP_VERSION__: JSON.stringify(packageJson.version),
    __APP_GIT_SHA__: JSON.stringify(gitSha),
    __APP_RELEASE__: JSON.stringify(releaseTag),
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;

          if (
            id.includes("/react/") ||
            id.includes("react-dom") ||
            id.includes("scheduler") ||
            id.includes("react-router")
          ) {
            return "react-core";
          }

          if (id.includes("@radix-ui")) return "radix-ui";
          if (id.includes("@tanstack/react-query")) return "react-query";
          if (id.includes("recharts") || id.includes("/d3-")) return "charts";
          if (id.includes("html2canvas")) return "capture";
          if (id.includes("date-fns")) return "date-utils";
          if (id.includes("zod")) return "schema";
          if (id.includes("lucide-react")) return "icons";

          return;
        },
      },
    },
  },
}));
