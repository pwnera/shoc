import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

// In development the console talks to a local shoc through this proxy, so the
// browser sees one origin, no CORS is involved and the session cookie is the
// page's own. In production the same is true: nginx serves the build and
// proxies /v1 and /auth to shoc. Sign-in needs SHOC_PUBLIC_URL set to this
// server's origin (http://localhost:5173), the only Origin it accepts.
const target = process.env.SHOC_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    rollupOptions: {
      output: {
        // Fold chunks under 8 KB (a sort helper, one icon, a card) into their neighbours: on plain HTTP/1.1 each
        // costs a request on a six-socket pool the API calls and the stream share.
        experimentalMinChunkSize: 8_000,
        // React, the router and TanStack Query change far less often than the
        // console, so they get their own chunk and stay cached across redeploys.
        // Icons share one chunk: one each, they were a dozen sub-kilobyte requests.
        manualChunks: (id) =>
          /node_modules\/(react|react-dom|scheduler|react-router|react-router-dom|@tanstack)\//.test(id)
            ? "vendor"
            : /node_modules\/lucide-react\//.test(id)
              ? "icons"
              : undefined,
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/v1": { target, changeOrigin: true },
      "/auth": { target, changeOrigin: true },
      "/healthz": { target, changeOrigin: true },
      "/metrics": { target, changeOrigin: true },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: false,
  },
});
