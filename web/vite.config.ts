import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// 本地开发：WHARF_URL=http://<控制面>:7700 npm run dev
const target = process.env.WHARF_URL ?? "http://127.0.0.1:7700";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: { proxy: { "/api": { target, changeOrigin: true } } },
  // 首屏 gzip 后约 200 KB（React 19 + Radix），对内网管理面板可以接受。
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 800 },
});
