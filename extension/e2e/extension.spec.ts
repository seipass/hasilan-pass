import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

import { chromium, expect, test, type BrowserContext, type Page } from "@playwright/test";

const API_ORIGIN = process.env.HP_E2E_API_URL ?? "http://127.0.0.1:18080";
const WEB_ORIGIN = process.env.HP_E2E_WEB_URL ?? "http://127.0.0.1:5173";
const SITE_ORIGIN = "http://127.0.0.1:19090";
const CROSS_SITE_ORIGIN = "http://localhost:19090";
const CHANNEL = "hasilan-pass-extension-v1";
const EXPECTED_EXTENSION_ID = "idknmeojelkflflogppfklcfbfamnbnb";
const chromeExecutable = process.env.HP_E2E_CHROME ?? chromium.executablePath();

test("register, enforce hostile-page boundaries, autofill, update, confirm in Web Vault, and relock", async ({}, testInfo) => {
  const extensionPath = testInfo.outputPath("unpacked-extension");
  const profilePath = testInfo.outputPath("chrome-profile");
  prepareTestExtension(extensionPath);
  mkdirSync(profilePath, { recursive: true });

  const context = await chromium.launchPersistentContext(profilePath, {
    executablePath: chromeExecutable,
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  try {
    const extensionId = await discoverExtensionId(context);
    expect(extensionId).toBe(EXPECTED_EXTENSION_ID);
    const popup = await context.newPage();
    const sentBodies: string[] = [];
    context.on("request", (request) => {
      if (request.url().startsWith(`${API_ORIGIN}/api/`)) sentBodies.push(request.postData() ?? "");
    });

    const unique = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
    const email = `extension-e2e-${unique}@example.test`;
    const masterPassword = `extension master password ${unique}!`;
    const firstPassword = `first-extension-secret-${unique}!`;
    const updatedPassword = `updated-extension-secret-${unique}!`;
    const hostilePassword = `hostile-shadow-secret-${unique}!`;
    const siteUrl = `${SITE_ORIGIN}/login.html`;

    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await popup.getByRole("button", { name: "Create", exact: true }).click();
    await popup.getByLabel("Server URL").fill(API_ORIGIN);
    await popup.getByLabel("Email").fill(email);
    await popup.getByLabel("Master password").fill(masterPassword);
    await popup.getByRole("button", { name: "Create vault" }).click();
    await expect(popup.getByPlaceholder("Search vault")).toBeVisible();

    await popup.getByRole("button", { name: /New/u }).click();
    await popup.getByLabel("Name", { exact: true }).fill("Extension E2E");
    await popup.getByLabel("Username").fill("alice-extension");
    await popup.getByLabel("Password", { exact: true }).fill(firstPassword);
    await popup.getByLabel("Website URL").fill(siteUrl);
    await popup.getByRole("button", { name: "Encrypt and save" }).click();
    await expect(popup.getByRole("heading", { name: "Extension E2E" })).toBeVisible();

    const site = await context.newPage();
    await site.goto(siteUrl);
    await site.bringToFront();
    const tabId = await activeTabId(popup);
    await extensionRequest(popup, { type: "REGISTER_SITE", matchPattern: `${SITE_ORIGIN}/*`, tabId });

    const username = site.getByLabel("Username");
    const password = site.getByLabel("Password");
    await username.focus();
    await username.press("ArrowDown");
    await username.press("Enter");
    await expect(username).toHaveValue("alice-extension");
    await expect(password).toHaveValue(firstPassword);

    await site.goto(`${SITE_ORIGIN}/hostile.html`);
    await site.bringToFront();
    await extensionRequest(popup, { type: "REGISTER_SITE", matchPattern: `${SITE_ORIGIN}/*`, tabId });

    const shadowUsername = site.getByLabel("Shadow username");
    const shadowPassword = site.getByLabel("Shadow password");
    await shadowUsername.focus();
    await expect(site.locator('[data-hasilan-pass="menu"]')).toBeAttached();
    await shadowUsername.press("ArrowDown");
    await shadowUsername.press("Enter");
    await expect(shadowUsername).toHaveValue("alice-extension");
    await expect(shadowPassword).toHaveValue(firstPassword);

    await shadowUsername.fill("shadow-capture");
    await shadowPassword.fill(hostilePassword);
    await shadowPassword.press("Enter");
    await expect.poll(async () => {
      const state = await extensionRequest<{ pending: null | { username: string | null } }>(popup, { type: "GET_STATE" });
      return state.pending?.username;
    }).toBe("shadow-capture");
    await extensionRequest(popup, { type: "DISMISS_PENDING" });
    await shadowPassword.press("Escape");

    const sameFrame = site.frameLocator('iframe[name="same-frame"]');
    const sameUsername = sameFrame.getByLabel("Frame username");
    const samePassword = sameFrame.getByLabel("Frame password");
    await sameUsername.focus();
    await expect(sameFrame.locator('[data-hasilan-pass="menu"]')).toBeAttached();
    await sameUsername.press("ArrowDown");
    await sameUsername.press("Enter");
    await expect(sameUsername).toHaveValue("alice-extension");
    await expect(samePassword).toHaveValue(firstPassword);

    const crossFrame = site.frameLocator('iframe[name="cross-frame"]');
    const crossUsername = crossFrame.getByLabel("Frame username");
    const crossPassword = crossFrame.getByLabel("Frame password");
    await crossUsername.focus();
    await crossUsername.press("ArrowDown");
    await crossUsername.press("Enter");
    await expect(crossUsername).toHaveValue("");
    await expect(crossPassword).toHaveValue("");

    await expect.poll(async () => site.evaluate(() => {
      return (window as typeof window & { __hasilanObservedMenus: unknown[] }).__hasilanObservedMenus.length;
    })).toBeGreaterThan(0);
    const observedMenus = await site.evaluate(() => {
      return (window as typeof window & {
        __hasilanObservedMenus: Array<{ readableShadow: boolean; readableText: string }>;
      }).__hasilanObservedMenus;
    });
    expect(observedMenus.every((menu) => !menu.readableShadow && menu.readableText === "")).toBe(true);

    const frameProbes = await executeForgedFrameRequests(popup, tabId, siteUrl);
    expect(frameProbes).toHaveLength(3);
    expect(frameProbes.some((probe) => probe.href.startsWith(`${CROSS_SITE_ORIGIN}/`))).toBe(true);
    for (const probe of frameProbes) {
      expect(probe.contentLoaded).toBe(true);
      expect(probe.response.ok).toBe(false);
      expect(probe.response.error).toContain("did not match the requesting frame");
    }

    await site.goto(siteUrl);
    await site.bringToFront();
    await username.focus();
    await expect(site.locator('[data-hasilan-pass="menu"]')).toBeAttached();
    await username.press("ArrowDown");
    await username.press("Enter");
    await expect(username).toHaveValue("alice-extension");
    await expect(password).toHaveValue(firstPassword);

    const createConfirmationPromise = context.waitForEvent("page");
    await site.getByRole("button", { name: "Create passkey" }).click();
    const createConfirmation = await createConfirmationPromise;
    await createConfirmation.waitForURL(/\/confirm\.html#/u);
    await expect(createConfirmation.getByRole("heading", { name: "Hasilan E2E RP" })).toBeVisible();
    await createConfirmation.getByLabel("Master password").fill(masterPassword);
    await createConfirmation.getByRole("button", { name: "Verify and create" }).click();
    await expect(site.getByText("Passkey created", { exact: true })).toBeVisible();

    const assertionConfirmationPromise = context.waitForEvent("page");
    await site.getByRole("button", { name: "Use passkey" }).click();
    const assertionConfirmation = await assertionConfirmationPromise;
    await assertionConfirmation.waitForURL(/\/confirm\.html#/u);
    await assertionConfirmation.getByLabel("Master password").fill(masterPassword);
    await assertionConfirmation.getByRole("button", { name: "Verify and continue" }).click();
    await expect(site.getByText("Passkey asserted", { exact: true })).toBeVisible();

    const passkeyEvidence = await site.evaluate(() => ({
      registration: (window as typeof window & { __hasilanPasskeyRegistration: { json: Record<string, unknown>; publicKey: string } }).__hasilanPasskeyRegistration,
      assertion: (window as typeof window & { __hasilanPasskeyAssertion: { json: Record<string, unknown>; challenge: string } }).__hasilanPasskeyAssertion,
    }));
    verifyPasskeyEvidence(passkeyEvidence, SITE_ORIGIN);
    const passkeyItems = await extensionRequest<Array<{ passkeyCount: number }>>(popup, {
      type: "LIST_ITEMS",
      query: "",
      category: "passkeys",
    });
    expect(passkeyItems).toHaveLength(1);
    expect(passkeyItems[0]?.passkeyCount).toBe(1);

    await password.fill(updatedPassword);
    await password.press("Escape");
    await site.getByRole("button", { name: "Sign in" }).click();
    await expect(site.getByText("Submitted locally")).toBeVisible();
    await expect.poll(async () => {
      const state = await extensionRequest<{ pending: null | { username: string | null } }>(popup, { type: "GET_STATE" });
      return state.pending?.username;
    }).toBe("alice-extension");

    await popup.reload();
    await popup.getByRole("button", { name: "Update Extension E2E" }).click();
    await expect(popup.getByText("Saved password updated.")).toBeVisible();
    await popup.getByRole("button", { name: /Extension E2E/u }).click();
    await popup.getByRole("button", { name: "Show" }).click();
    await expect(popup.getByText(updatedPassword, { exact: true })).toBeVisible();

    const webVault = await context.newPage();
    await webVault.goto(WEB_ORIGIN);
    await webVault.getByLabel("Email address").fill(email);
    await webVault.getByLabel("Master password", { exact: true }).fill(masterPassword);
    await webVault.getByRole("button", { name: "Unlock vault" }).click();
    await expect(webVault.getByRole("button", { name: /Extension E2E/u })).toBeVisible();
    await webVault.getByRole("button", { name: /Extension E2E/u }).click();
    await webVault.getByRole("button", { name: "Reveal" }).click();
    await expect(webVault.locator(".secret-value")).toHaveText(updatedPassword);

    await popup.getByRole("button", { name: "Back" }).click();
    await popup.getByRole("button", { name: "Lock" }).click();
    await expect(popup.getByRole("button", { name: "Unlock vault" })).toBeVisible();

    const transmitted = sentBodies.join("\n");
    expect(transmitted).not.toContain(masterPassword);
    expect(transmitted).not.toContain(firstPassword);
    expect(transmitted).not.toContain(updatedPassword);
    expect(transmitted).not.toContain(hostilePassword);
    expect(transmitted).not.toContain("alice-extension");
    expect(transmitted).not.toContain("shadow-capture");
    expect(transmitted).not.toContain("alice-passkey-user");
  } finally {
    await context.close();
  }
});

function prepareTestExtension(destination: string): void {
  const built = fileURLToPath(new URL("../dist", import.meta.url));
  cpSync(built, destination, { recursive: true });
  const manifestPath = `${destination}/manifest.json`;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { host_permissions?: string[] };
  manifest.host_permissions = [`${API_ORIGIN}/*`, `${SITE_ORIGIN}/*`, `${CROSS_SITE_ORIGIN}/*`];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

function verifyPasskeyEvidence(
  evidence: {
    registration: { json: Record<string, unknown>; publicKey: string };
    assertion: { json: Record<string, unknown>; challenge: string };
  },
  origin: string,
): void {
  const registrationJson = evidence.registration.json as {
    id: string;
    response: { clientDataJSON: string };
  };
  const assertionJson = evidence.assertion.json as {
    id: string;
    response: { clientDataJSON: string; authenticatorData: string; signature: string };
  };
  expect(assertionJson.id).toBe(registrationJson.id);
  const clientData = Buffer.from(assertionJson.response.clientDataJSON, "base64url");
  const parsedClientData = JSON.parse(clientData.toString("utf8")) as {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin: boolean;
  };
  expect(parsedClientData).toMatchObject({
    type: "webauthn.get",
    challenge: evidence.assertion.challenge,
    origin,
    crossOrigin: false,
  });
  const authenticatorData = Buffer.from(assertionJson.response.authenticatorData, "base64url");
  expect(authenticatorData.subarray(0, 32)).toEqual(createHash("sha256").update("127.0.0.1").digest());
  expect((authenticatorData[32] ?? 0) & 0b0000_0101).toBe(0b0000_0101);
  const signedData = Buffer.concat([
    authenticatorData,
    createHash("sha256").update(clientData).digest(),
  ]);
  const publicKey = createPublicKey({
    key: Buffer.from(evidence.registration.publicKey, "base64url"),
    format: "der",
    type: "spki",
  });
  expect(verifySignature(
    "sha256",
    signedData,
    publicKey,
    Buffer.from(assertionJson.response.signature, "base64url"),
  )).toBe(true);
}

async function discoverExtensionId(context: BrowserContext): Promise<string> {
  let worker = context.serviceWorkers()[0];
  worker ??= await context.waitForEvent("serviceworker", { timeout: 20_000 });
  return new URL(worker.url()).host;
}

async function activeTabId(popup: Page): Promise<number> {
  const tabId = await popup.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.id;
  });
  if (tabId === undefined) throw new Error("The test page did not have an active browser tab.");
  return tabId;
}

async function extensionRequest<T = unknown>(popup: Page, body: Record<string, unknown>): Promise<T> {
  const response = await popup.evaluate(async ({ channel, request }) => {
    return chrome.runtime.sendMessage({ channel, ...request });
  }, { channel: CHANNEL, request: body }) as { ok: boolean; data?: T; error?: string };
  if (!response.ok) throw new Error(response.error ?? "Extension request failed.");
  return response.data as T;
}

async function executeForgedFrameRequests(
  popup: Page,
  tabId: number,
  claimedPageUrl: string,
): Promise<Array<{
  frameId: number;
  href: string;
  contentLoaded: boolean;
  response: { ok: boolean; error?: string };
}>> {
  return popup.evaluate(async ({ channel, targetTabId, pageUrl }) => {
    const results = await chrome.scripting.executeScript({
      target: { tabId: targetTabId, allFrames: true },
      world: "ISOLATED",
      func: async (requestChannel: string, forgedPageUrl: string) => {
        const response = await chrome.runtime.sendMessage({
          channel: requestChannel,
          type: "CREDENTIALS_FOR_PAGE",
          pageUrl: forgedPageUrl,
        }) as { ok: boolean; error?: string };
        return {
          href: location.href,
          contentLoaded: (globalThis as typeof globalThis & { __hasilanPassContentV1?: boolean })
            .__hasilanPassContentV1 === true,
          response,
        };
      },
      args: [channel, pageUrl],
    });
    return results.flatMap(({ frameId, result }) => result === undefined ? [] : [{ frameId, ...result }]);
  }, { channel: CHANNEL, targetTabId: tabId, pageUrl: claimedPageUrl });
}
