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
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          charts: ["recharts"],
          mermaid: ["mermaid"],
        },
      },
    },
  },
});
