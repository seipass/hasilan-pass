export const DEFAULT_LOCK_MINUTES = 15;

export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | 240 | null;

export function normalizeAutoLock(value: number | null): AutoLockSetting {
  if (value === null) return null;
  if (value === 1 || value === 5 || value === 15 || value === 30 || value === 60 || value === 240) return value;
  throw new Error("Choose an automatic-lock delay from the available options.");
}

export function persistedAutoLock(value: unknown): AutoLockSetting {
  if (value === null) return null;
  if (value === undefined) return DEFAULT_LOCK_MINUTES;
  return value === 1 || value === 5 || value === 15 || value === 30 || value === 60 || value === 240
    ? value
    : DEFAULT_LOCK_MINUTES;
}

/** Preserve `null` (Never) while supplying the default only for old settings. */
export function effectiveAutoLock(value: AutoLockSetting | undefined): AutoLockSetting {
  return value === undefined ? DEFAULT_LOCK_MINUTES : value;
}
