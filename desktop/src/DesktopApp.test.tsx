import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { DesktopStatus, ItemSummary, OrganizationCatalog, VaultItem } from "./ipc";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));

import { DesktopApp } from "./DesktopApp";

const lockedStatus: DesktopStatus = {
  unlocked: false,
  online: false,
  serverUrl: null,
  email: null,
  itemCount: 0,
  pendingCount: 0,
  conflictCount: 0,
  autoLockMinutes: 15,
  rememberUnlock: false,
  lastSyncAt: null,
  profiles: [],
};

const unlockedStatus: DesktopStatus = {
  ...lockedStatus,
  unlocked: true,
  online: true,
  serverUrl: "https://vault.example.test",
  email: "alice@example.test",
  itemCount: 1,
  lastSyncAt: "2026-08-12T00:00:00Z",
  profiles: [
    {
      scope: "https://vault.example.test|alice@example.test",
      serverUrl: "https://vault.example.test",
      email: "alice@example.test",
      active: true,
    },
  ],
};

const summary: ItemSummary = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Example account",
  itemType: 1,
  username: "alice",
  primaryUri: "https://accounts.example.test",
  favorite: true,
  deletedDate: null,
  hasTotp: false,
  passkeyCount: 0,
  objectRevision: 7,
  pending: false,
  conflicted: false,
  organizationId: null,
  collectionIds: [],
};

const emptyCatalog: OrganizationCatalog = { organizations: [], collections: [], folders: [] };

const item: VaultItem = {
  schemaVersion: 1,
  id: summary.id,
  folderId: null,
  organizationId: null,
  collectionIds: [],
  name: summary.name,
  notes: "Private note",
  favorite: true,
  reprompt: 0,
      fields: [],
      passwordHistory: [],
      attachments: [],
      data: {
    kind: "login",
    value: {
      username: "alice",
      password: "correct horse battery staple",
      uris: [{ uri: "https://accounts.example.test", match: null }],
      totp: null,
      fido2Credentials: [],
    },
  },
  creationDate: "2026-08-12T00:00:00Z",
  revisionDate: "2026-08-12T00:00:00Z",
  deletedDate: null,
  archivedDate: null,
};

let lockListener: (() => void) | null;

beforeEach(() => {
  lockListener = null;
  mocks.invoke.mockReset();
  mocks.listen.mockReset();
  mocks.listen.mockImplementation(async (event: string, listener: () => void) => {
    if (event === "vault-locked") lockListener = listener;
    return () => undefined;
  });
});

describe("DesktopApp", () => {
  it("resumes a remembered session and unlocks after a foreground transition", async () => {
    const rememberedStatus: DesktopStatus = {
      ...lockedStatus,
      online: false,
      serverUrl: "https://vault.example.test",
      email: "alice@example.test",
      rememberUnlock: true,
      profiles: unlockedStatus.profiles,
    };
    const onlineLockedStatus: DesktopStatus = { ...rememberedStatus, online: true };
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return rememberedStatus;
      if (command === "resume_session") return onlineLockedStatus;
      if (command === "unlock_with_device_key") return unlockedStatus;
      if (command === "list_items") return [summary];
      if (command === "organization_catalog") return emptyCatalog;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);

    expect(await screen.findByText("Example account")).toBeTruthy();
    expect(mocks.invoke).toHaveBeenCalledWith("resume_session");
    expect(mocks.invoke).toHaveBeenCalledWith("unlock_with_device_key");
  });

  it("logs in through the native boundary and only decrypts an explicitly selected item", async () => {
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return lockedStatus;
      if (command === "login") return unlockedStatus;
      if (command === "list_items") return [summary];
      if (command === "organization_catalog") return emptyCatalog;
      if (command === "get_item") return item;
      if (command === "copy_secret") return undefined;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    const unlock = await screen.findByRole("button", { name: "Unlock vault" });
    fireEvent.change(screen.getByLabelText("Server URL"), { target: { value: "https://vault.example.test" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "alice@example.test" } });
    fireEvent.change(screen.getByLabelText("Master password"), { target: { value: "master-password" } });
    fireEvent.click(unlock);

    expect(await screen.findByText("Example account")).toBeTruthy();
    expect(mocks.invoke).toHaveBeenCalledWith("login", {
      serverUrl: "https://vault.example.test",
      email: "alice@example.test",
      masterPassword: "master-password",
      totpCode: null,
      recoveryCode: null,
    });
    expect(screen.queryByText("Private note")).toBeNull();

    fireEvent.click(screen.getByText("Example account"));
    expect(await screen.findByText("Private note")).toBeTruthy();
    expect(screen.queryByText("correct horse battery staple")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
    expect(screen.getByText("correct horse battery staple")).toBeTruthy();

    const copyButtons = screen.getAllByRole("button", { name: "Copy" });
    fireEvent.click(copyButtons[1]);
    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("copy_secret", {
      value: "correct horse battery staple",
    }));
  });

  it("renders native errors as inert text", async () => {
    const payload = '<img src=x onerror="globalThis.compromised=true">';
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return lockedStatus;
      if (command === "login") throw payload;
      throw new Error(`Unexpected command: ${command}`);
    });

    const view = render(<DesktopApp />);
    await screen.findByRole("button", { name: "Unlock vault" });
    fireEvent.change(screen.getByLabelText("Server URL"), { target: { value: "https://vault.example.test" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "alice@example.test" } });
    fireEvent.change(screen.getByLabelText("Master password"), { target: { value: "incorrect-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock vault" }));

    expect((await screen.findByRole("alert")).textContent).toContain(payload);
    expect(view.container.querySelector('img[src="x"]')).toBeNull();
    expect(view.container.querySelector("img[onerror]")).toBeNull();
  });

  it("creates a login in a writable organization collection", async () => {
    const organizationId = "22222222-2222-4222-8222-222222222222";
    const collectionId = "33333333-3333-4333-8333-333333333333";
    const catalog: OrganizationCatalog = {
      organizations: [{ id: organizationId, name: "Engineering", role: "user" }],
      collections: [{ id: collectionId, organizationId, name: "Production", readOnly: false, hidePasswords: false, manage: false }],
      folders: [],
    };
    const sharedItem: VaultItem = { ...item, id: "44444444-4444-4444-8444-444444444444", name: "Shared deploy", organizationId, collectionIds: [collectionId] };
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return unlockedStatus;
      if (command === "list_items") return [];
      if (command === "organization_catalog") return catalog;
      if (command === "save_login") return sharedItem;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    fireEvent.click(await screen.findByRole("button", { name: /New login/u }));
    fireEvent.change(screen.getByLabelText("Vault destination"), { target: { value: `${organizationId}:${collectionId}` } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Shared deploy" } });
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "deployer" } });
    fireEvent.click(screen.getByRole("button", { name: "Encrypt and save" }));

    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("save_login", {
      draft: expect.objectContaining({
        id: null,
        name: "Shared deploy",
        username: "deployer",
        organizationId,
        collectionIds: [collectionId],
      }),
    }));
  });

  it("creates a secure note through the shared typed-item command", async () => {
    const note: VaultItem = {
      ...item,
      id: "55555555-5555-4555-8555-555555555555",
      name: "Emergency instructions",
      data: { kind: "secureNote", value: { noteType: 0 } },
    };
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return unlockedStatus;
      if (command === "list_items") return [];
      if (command === "organization_catalog") return emptyCatalog;
      if (command === "save_item") return note;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    fireEvent.change(await screen.findByLabelText("Create vault item type"), { target: { value: "secureNote" } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Emergency instructions" } });
    fireEvent.change(screen.getByLabelText("Notes"), { target: { value: "Call the family contact" } });
    fireEvent.click(screen.getByRole("button", { name: "Encrypt and save" }));

    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("save_item", {
      draft: expect.objectContaining({
        id: null,
        name: "Emergency instructions",
        notes: "Call the family contact",
        data: { kind: "secureNote", value: { noteType: 0 } },
      }),
    }));
  });

  it("dismisses a vault editor when Android Back pops its non-secret history entry", async () => {
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return unlockedStatus;
      if (command === "list_items") return [];
      if (command === "organization_catalog") return emptyCatalog;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    fireEvent.click(await screen.findByRole("button", { name: /New login/u }));
    expect(await screen.findByRole("heading", { name: "New login" })).toBeTruthy();
    window.dispatchEvent(new PopStateEvent("popstate"));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "New login" })).toBeNull());
  });

  it("creates a personal folder through the encrypted shared-core command", async () => {
    const createdFolder = { id: "66666666-6666-4666-8666-666666666666", name: "Travel" };
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return unlockedStatus;
      if (command === "list_items") return [];
      if (command === "organization_catalog") return { ...emptyCatalog, folders: [createdFolder] };
      if (command === "save_folder") return createdFolder;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    fireEvent.click((await screen.findAllByRole("button", { name: /Settings/u }))[0]);
    fireEvent.change(screen.getByLabelText("New folder name"), { target: { value: "Travel" } });
    fireEvent.click(screen.getByRole("button", { name: "Create folder" }));

    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("save_folder", {
      draft: { id: null, name: "Travel" },
    }));
  });

  it("clears decrypted UI state when the native idle monitor emits vault-locked", async () => {
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "status") return unlockedStatus;
      if (command === "list_items") return [summary];
      if (command === "organization_catalog") return emptyCatalog;
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<DesktopApp />);
    expect(await screen.findByText("Example account")).toBeTruthy();
    expect(lockListener).not.toBeNull();

    act(() => lockListener?.());
    expect(await screen.findByRole("button", { name: "Unlock vault" })).toBeTruthy();
    expect(screen.queryByText("Example account")).toBeNull();
  });
});
