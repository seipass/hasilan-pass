import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "HP_");
  return {
    plugins: [react()],
    build: {
      target: "es2023",
      sourcemap: true,
    },
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target: env.HP_DEV_API_TARGET ?? "http://127.0.0.1:8080",
          changeOrigin: false,
        },
      },
    },
    test: {
      environment: "jsdom",
      exclude: ["e2e/**"],
      restoreMocks: true,
      setupFiles: ["./src/test-setup.ts"],
    },
  };
});
