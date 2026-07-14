import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api → backend in dev so the same code works in dev and prod.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET || "http://localhost:8443",
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // The only large chunk left is three.js (~900 KB), and it is intentionally
    // off the critical path — lazy-loaded behind a dynamic import (see the
    // Dashboard's lazy NetworkTopology3D). Limit sits just above it so a NEW
    // oversized chunk in the eager path would still warn.
    chunkSizeWarningLimit: 950,
    rollupOptions: {
      output: {
        // Long-lived vendor chunks that change rarely → better browser caching.
        // three.js / @react-three are intentionally NOT listed: they auto-split
        // into the lazy topology chunk via the dynamic import and must stay async.
        // Function form (object form was dropped when Vite 8 moved to Rolldown).
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (id.includes("framer-motion")) return "motion";
          if (/[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/.test(id))
            return "react";
        },
      },
    },
  },
});
