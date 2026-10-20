import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 本地开发：WHARF_URL=http://<控制面>:7700 npm run dev
const target = process.env.WHARF_URL ?? "http://127.0.0.1:7700";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target, changeOrigin: true } } },
  build: { outDir: "dist", emptyOutDir: true },
});
