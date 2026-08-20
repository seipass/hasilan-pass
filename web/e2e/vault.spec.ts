import { expect, test, type Page } from "@playwright/test";

test("register, encrypt, sync, relogin, edit, and trash a credential", async ({ page }) => {
  const unique = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const email = `e2e-${unique}@example.test`;
  const masterPassword = `e2e master password ${unique}!`;
  const firstPassword = "  exact password with spaces  ";
  const updatedPassword = `updated-${unique}!`;
  const folderName = `E2E Folder ${unique}`;
  const renamedFolderName = `E2E Folder renamed ${unique}`;
  const sentBodies: string[] = [];

  page.on("request", (request) => {
    if (request.url().includes("/api/")) sentBodies.push(request.postData() ?? "");
  });

  await page.goto("/");
  await page.getByRole("tab", { name: "Create vault" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  await page.getByLabel("Confirm master password").fill(masterPassword);
  await page.getByRole("button", { name: "Create encrypted vault" }).click();

  await expect(page.getByRole("heading", { name: "All items" })).toBeVisible();
  await page.getByRole("button", { name: "Manage folders" }).click();
  await page.getByLabel("New folder name").fill(folderName);
  await page.getByRole("button", { name: "Create encrypted folder" }).click();
  await expect(page.locator(".folder-row").filter({ hasText: folderName })).toBeVisible();
  await page.getByLabel("Close dialog").click();

  await page.getByRole("button", { name: "New login" }).click();
  await page.getByLabel("Personal folder").selectOption({ label: folderName });
  await page.getByLabel("Name", { exact: true }).fill("E2E Example");
  await page.getByLabel("Username").fill("alice-e2e");
  await page.locator('.dialog-card input[name="password"]').fill(firstPassword);
  await page.getByLabel("Website URL").fill("https://login.example.com/account");
  await page.getByLabel("Authenticator key or otpauth URI").fill("JBSWY3DPEHPK3PXP");
  await page.getByLabel("Notes").fill("Synthetic browser journey");
  await page.getByRole("button", { name: "Encrypt and save" }).click();

  await page.getByRole("button", { name: folderName, exact: true }).click();
  await expect(page.getByRole("button", { name: /E2E Example/ })).toBeVisible();
  await page.getByRole("button", { name: /E2E Example/ }).click();
  await expect(page.locator(".detail-panel").getByText("alice-e2e", { exact: true })).toBeVisible();
  await expect(page.locator(".totp-code")).toHaveText(/^\d{6}$/u);
  await page.getByRole("button", { name: "Reveal" }).click();
  await expect(page.locator(".secret-value")).toHaveText(firstPassword);

  await page.getByRole("button", { name: "Edit item" }).click();
  await page.getByLabel("Name", { exact: true }).fill("E2E Example updated");
  await page.locator('.dialog-card input[name="password"]').fill(updatedPassword);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(page.getByRole("heading", { name: "E2E Example updated" })).toBeVisible();

  await page.reload();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  await page.getByRole("button", { name: "Unlock vault" }).click();
  await expect(page.getByRole("button", { name: folderName, exact: true })).toBeVisible();
  await page.getByRole("button", { name: folderName, exact: true }).click();
  await expect(page.getByRole("button", { name: /E2E Example updated/ })).toBeVisible();

  await page.getByRole("button", { name: "Manage folders" }).click();
  const folderRow = page.locator(".folder-row").filter({ hasText: folderName });
  await folderRow.getByRole("button", { name: "Rename" }).click();
  await page.locator(".folder-row.editing input[name='name']").fill(renamedFolderName);
  await page.locator(".folder-row.editing").getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".folder-row").filter({ hasText: renamedFolderName })).toBeVisible();
  await page.getByLabel("Close dialog").click();

  await page.reload();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  await page.getByRole("button", { name: "Unlock vault" }).click();
  await page.getByRole("button", { name: renamedFolderName, exact: true }).click();
  await expect(page.getByRole("button", { name: /E2E Example updated/ })).toBeVisible();

  await page.getByRole("button", { name: "Manage folders" }).click();
  const renamedFolderRow = page.locator(".folder-row").filter({ hasText: renamedFolderName });
  page.once("dialog", (dialog) => void dialog.accept());
  await renamedFolderRow.getByRole("button", { name: "Delete" }).click();
  await expect(renamedFolderRow).toHaveCount(0);
  await page.getByLabel("Close dialog").click();
  await expect(page.getByRole("button", { name: renamedFolderName, exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "All items", exact: true }).click();
  await expect(page.getByRole("button", { name: /E2E Example updated/ })).toBeVisible();

  await page.getByRole("button", { name: /E2E Example updated/ }).click();
  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Move to trash" }).click();
  await page.getByRole("button", { name: "Trash", exact: true }).click();
  await expect(page.getByRole("button", { name: /E2E Example updated/ })).toBeVisible();

  const transmitted = sentBodies.join("\n");
  expect(transmitted).not.toContain(masterPassword);
  expect(transmitted).not.toContain(firstPassword);
  expect(transmitted).not.toContain(updatedPassword);
  expect(transmitted).not.toContain("alice-e2e");
  expect(transmitted).not.toContain(folderName);
  expect(transmitted).not.toContain(renamedFolderName);
});

test("create, edit, encrypt, and reload every typed vault item", async ({ page }) => {
  const unique = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const email = `typed-e2e-${unique}@example.test`;
  const masterPassword = `typed e2e master password ${unique}!`;
  const secureNoteName = `Typed secure note ${unique}`;
  const secureNoteSecret = `updated secure note body ${unique}`;
  const cardName = `Typed payment card ${unique}`;
  const cardNumber = "4000000000000002";
  const updatedCardNumber = "5555555555554444";
  const identityName = `Typed identity ${unique}`;
  const passportNumber = `passport-${unique}`;
  const updatedPassportNumber = `passport-updated-${unique}`;
  const sshName = `Typed SSH key ${unique}`;
  const privateKey = `-----BEGIN PRIVATE KEY-----\nprivate-${unique}\n-----END PRIVATE KEY-----`;
  const updatedPrivateKey = `-----BEGIN PRIVATE KEY-----\nprivate-updated-${unique}\n-----END PRIVATE KEY-----`;
  const sentBodies: string[] = [];

  page.on("request", (request) => {
    if (request.url().includes("/api/")) sentBodies.push(request.postData() ?? "");
  });

  await registerPage(page, email, masterPassword);

  await openNewItem(page, "secureNote", "New secure note");
  await page.getByLabel("Name", { exact: true }).fill(secureNoteName);
  await page.getByRole("textbox", { name: "Secure note", exact: true }).fill(`initial secure note body ${unique}`);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Edit item" }).click();
  await page.getByRole("textbox", { name: "Secure note", exact: true }).fill(secureNoteSecret);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Close item" }).click();

  await openNewItem(page, "card", "New payment card");
  await page.getByLabel("Name", { exact: true }).fill(cardName);
  await page.getByLabel("Cardholder name").fill("Alice Typed");
  await page.getByLabel("Brand").fill("Fixture Card");
  await page.getByLabel("Card number").fill(cardNumber);
  await page.getByLabel("Expiration month").fill("12");
  await page.getByLabel("Expiration year").fill("2032");
  await page.getByLabel("Security code").fill("987");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Edit item" }).click();
  await page.getByLabel("Card number").fill(updatedCardNumber);
  await page.getByLabel("Security code").fill("654");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Close item" }).click();

  await openNewItem(page, "identity", "New identity");
  await page.getByLabel("Name", { exact: true }).fill(identityName);
  await page.getByLabel("First name").fill("Alice");
  await page.getByLabel("Last name").fill("Typed");
  await page.getByLabel("Email").fill("alice.typed@example.test");
  await page.getByLabel("Address line 1").fill("1 Encrypted Road");
  await page.getByLabel("Passport number").fill(passportNumber);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Edit item" }).click();
  await page.getByLabel("Passport number").fill(updatedPassportNumber);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Close item" }).click();

  await openNewItem(page, "sshKey", "New ssh key");
  await page.getByLabel("Name", { exact: true }).fill(sshName);
  await page.getByLabel("Private key").fill(privateKey);
  await page.getByLabel("Public key").fill(`ssh-ed25519 public-${unique}`);
  await page.getByLabel("Fingerprint").fill(`SHA256:${unique}`);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await page.getByRole("button", { name: "Edit item" }).click();
  await page.getByLabel("Private key").fill(updatedPrivateKey);
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText(/Item encrypted and synchronized/u)).toBeVisible();

  await page.reload();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  await page.getByRole("button", { name: "Unlock vault" }).click();

  await page.getByRole("button", { name: new RegExp(secureNoteName, "u") }).click();
  await expect(page.getByText(secureNoteSecret, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Close item" }).click();

  await page.getByRole("button", { name: new RegExp(cardName, "u") }).click();
  await page.getByRole("button", { name: "Reveal private fields" }).click();
  await expect(page.getByText(updatedCardNumber, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Close item" }).click();

  await page.getByRole("button", { name: new RegExp(identityName, "u") }).click();
  await page.getByRole("button", { name: "Reveal private fields" }).click();
  await expect(page.getByText(updatedPassportNumber, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Close item" }).click();

  await page.getByRole("button", { name: new RegExp(sshName, "u") }).click();
  await page.getByRole("button", { name: "Reveal private fields" }).click();
  await expect(page.getByText(`private-updated-${unique}`, { exact: false })).toBeVisible();

  const transmitted = sentBodies.join("\n");
  for (const plaintext of [
    masterPassword,
    secureNoteName,
    secureNoteSecret,
    cardName,
    cardNumber,
    updatedCardNumber,
    identityName,
    passportNumber,
    updatedPassportNumber,
    sshName,
    privateKey,
    updatedPrivateKey,
  ]) {
    expect(transmitted).not.toContain(plaintext);
  }
});

test("create an organization, invite and confirm a member, then share encrypted login", async ({ browser }) => {
  const unique = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  const ownerEmail = `org-owner-${unique}@example.test`;
  const memberEmail = `org-member-${unique}@example.test`;
  const ownerPassword = `owner master password ${unique}!`;
  const memberPassword = `member master password ${unique}!`;
  const sharedPassword = `shared-organization-secret-${unique}`;
  const sentBodies: string[] = [];
  const ownerContext = await browser.newContext();
  const memberContext = await browser.newContext();
  const ownerPage = await ownerContext.newPage();
  const memberPage = await memberContext.newPage();
  for (const page of [ownerPage, memberPage]) {
    page.on("request", (request) => {
      if (request.url().includes("/api/")) sentBodies.push(request.postData() ?? "");
    });
  }

  await registerPage(ownerPage, ownerEmail, ownerPassword);
  await ownerPage.getByRole("button", { name: "Organizations" }).click();
  await ownerPage.getByLabel("New organization").fill("E2E Engineering");
  await ownerPage.getByRole("button", { name: "Create", exact: true }).click();
  await expect(ownerPage.locator(".organization-detail h3")).toHaveText("E2E Engineering");
  await ownerPage.getByPlaceholder("Collection name").fill("Shared logins");
  await ownerPage.getByRole("button", { name: "Add collection" }).click();
  await expect(ownerPage.locator(".collection-chips")).toContainText("Shared logins");

  await registerPage(memberPage, memberEmail, memberPassword);
  await ownerPage.getByPlaceholder("person@example.com").fill(memberEmail);
  await ownerPage.getByRole("button", { name: "Create invitation" }).click();
  const invitationToken = await ownerPage.locator(".delivery-token code").innerText();
  expect(invitationToken.length).toBeGreaterThan(30);

  await memberPage.getByRole("button", { name: /Lock vault/u }).click();
  await memberPage.goto(`/#invitation=${invitationToken}`);
  await memberPage.getByLabel("Email address").fill(memberEmail);
  await memberPage.getByLabel("Master password", { exact: true }).fill(memberPassword);
  await memberPage.getByRole("button", { name: "Unlock vault" }).click();
  await expect(memberPage.getByLabel("Invitation token")).toHaveValue(invitationToken);
  await memberPage.getByRole("button", { name: "Accept", exact: true }).click();
  await expect(memberPage.getByText(/Invitation accepted/u)).toBeVisible();
  await expect(memberPage).not.toHaveURL(/#invitation=/u);

  await ownerPage.getByLabel("Close dialog").click();
  await ownerPage.getByRole("button", { name: "Organizations" }).click();
  const memberRow = ownerPage.locator(".member-row").filter({ hasText: memberEmail });
  await memberRow.getByRole("button", { name: "Confirm" }).click();
  await expect(memberRow).toContainText("confirmed");
  await ownerPage.locator('select[name="collectionId"]').selectOption({ label: "Shared logins" });
  await ownerPage.locator('select[name="memberId"]').selectOption({ label: memberEmail });
  await ownerPage.getByRole("button", { name: "Apply access" }).click();
  await expect(ownerPage.getByText(/Collection access updated/u)).toBeVisible();
  await ownerPage.getByLabel("Close dialog").click();

  await ownerPage.getByRole("button", { name: "New login" }).click();
  await ownerPage.getByLabel("Vault destination").selectOption({ label: "E2E Engineering / Shared logins" });
  await ownerPage.getByLabel("Name", { exact: true }).fill("Shared E2E account");
  await ownerPage.getByLabel("Username").fill("shared-user");
  await ownerPage.locator('.dialog-card input[name="password"]').fill(sharedPassword);
  await ownerPage.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(ownerPage.getByRole("button", { name: /Shared E2E account/u })).toBeVisible();

  await memberPage.getByLabel("Close dialog").click();
  await memberPage.getByRole("button", { name: "Sync", exact: true }).click();
  await expect(memberPage.getByRole("button", { name: /Shared E2E account/u })).toBeVisible();
  await memberPage.getByRole("button", { name: /Shared E2E account/u }).click();
  await memberPage.getByRole("button", { name: "Reveal" }).click();
  await expect(memberPage.locator(".secret-value")).toHaveText(sharedPassword);

  const transmitted = sentBodies.join("\n");
  expect(transmitted).not.toContain(ownerPassword);
  expect(transmitted).not.toContain(memberPassword);
  expect(transmitted).not.toContain(sharedPassword);
  expect(transmitted).not.toContain("Shared E2E account");
  expect(transmitted).not.toContain("shared-user");
  await ownerContext.close();
  await memberContext.close();
});

async function registerPage(page: Page, email: string, masterPassword: string): Promise<void> {
  await page.goto("/");
  await page.getByRole("tab", { name: "Create vault" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Master password", { exact: true }).fill(masterPassword);
  await page.getByLabel("Confirm master password").fill(masterPassword);
  await page.getByRole("button", { name: "Create encrypted vault" }).click();
  await expect(page.getByRole("heading", { name: "All items" })).toBeVisible();
}

async function openNewItem(page: Page, value: string, buttonName: string): Promise<void> {
  await page.getByLabel("New item type").selectOption(value);
  await page.getByRole("button", { name: buttonName }).click();
}
