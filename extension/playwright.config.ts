import { defineConfig } from "@playwright/test";

const apiOrigin = process.env.HP_E2E_API_URL ?? "http://127.0.0.1:18080";
const webOrigin = process.env.HP_E2E_WEB_URL ?? "http://127.0.0.1:5173";

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  retries: process.env.CI === undefined ? 0 : 1,
  reporter: process.env.CI === undefined ? "line" : "github",
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "python3 -m http.server 19090 --bind 127.0.0.1 --directory e2e/site",
      url: "http://127.0.0.1:19090/login.html",
      reuseExistingServer: true,
      timeout: 15_000,
    },
    {
      command: "pnpm --dir ../web dev",
      url: webOrigin,
      reuseExistingServer: true,
      timeout: 30_000,
      env: { HP_DEV_API_TARGET: apiOrigin },
    },
  ],
});
