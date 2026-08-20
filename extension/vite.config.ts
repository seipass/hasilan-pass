import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const extensionRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root: extensionRoot,
  plugins: [react(), manifestPlugin()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2023",
    sourcemap: true,
    rollupOptions: {
      input: {
        confirm: fileURLToPath(new URL("./confirm.html", import.meta.url)),
        popup: fileURLToPath(new URL("./popup.html", import.meta.url)),
        background: fileURLToPath(new URL("./src/background.ts", import.meta.url)),
        content: fileURLToPath(new URL("./src/content.ts", import.meta.url)),
        "passkey-page": fileURLToPath(new URL("./src/passkey-page.ts", import.meta.url)),
      },
      output: {
        entryFileNames: "assets/[name].js",
        chunkFileNames: "assets/chunk-[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});

function manifestPlugin(): Plugin {
  return {
    name: "hasilan-extension-manifest",
    generateBundle() {
      const manifest = readFileSync(new URL("./manifest.json", import.meta.url), "utf8");
      this.emitFile({ type: "asset", fileName: "manifest.json", source: manifest });
    },
  };
}
