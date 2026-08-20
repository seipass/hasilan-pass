import init, { VaultRuntime } from "./generated/hasilan_wasm";

let initialization: Promise<void> | undefined;

export async function createVaultRuntime(): Promise<VaultRuntime> {
  initialization ??= init().then(() => undefined);
  await initialization;
  return new VaultRuntime();
}

export type SharedVaultRuntime = VaultRuntime;

