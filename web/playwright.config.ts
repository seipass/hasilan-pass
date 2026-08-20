import { defineConfig } from "@playwright/test";

const externalServer = process.env.HP_E2E_EXTERNAL_SERVER === "1";
const executablePath = process.env.HP_E2E_CHROME;

export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  retries: process.env.CI === undefined ? 0 : 1,
  reporter: process.env.CI === undefined ? "line" : "github",
  use: {
    baseURL: process.env.HP_E2E_BASE_URL ?? "http://127.0.0.1:5173",
    browserName: "chromium",
    headless: true,
    launchOptions: executablePath === undefined ? {} : { executablePath },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: externalServer
    ? undefined
    : {
        command: "pnpm dev",
        url: "http://127.0.0.1:5173",
        reuseExistingServer: true,
        timeout: 30_000,
      },
});

