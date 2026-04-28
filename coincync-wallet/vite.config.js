import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    hmr: {
      // Don't do full page reloads — just hot-swap components
      overlay: true,
    },
    watch: {
      // Don't watch Rust/Tauri source — prevents app restart on backend changes
      ignored: ["**/src-tauri/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: { target: ["es2021","chrome100","safari13"], minify: "esbuild" },
});
