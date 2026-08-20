import init, { VaultRuntime } from "./generated/hasilan_wasm";

let initialization: Promise<void> | undefined;

export async function createRuntime(): Promise<VaultRuntime> {
  initialization ??= init().then(() => undefined);
  await initialization;
  return new VaultRuntime();
}

export type ExtensionVaultRuntime = VaultRuntime;

