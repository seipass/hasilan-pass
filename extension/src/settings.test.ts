import { describe, expect, it } from "vitest";

import {
  DEFAULT_LOCK_MINUTES,
  effectiveAutoLock,
  normalizeAutoLock,
  persistedAutoLock,
} from "./settings";

describe("automatic-lock settings", () => {
  it("keeps Never as null through normalization and persistence", () => {
    expect(normalizeAutoLock(null)).toBeNull();
    expect(persistedAutoLock(null)).toBeNull();
    expect(effectiveAutoLock(null)).toBeNull();
  });

  it("uses the default only for missing legacy settings", () => {
    expect(effectiveAutoLock(undefined)).toBe(DEFAULT_LOCK_MINUTES);
    expect(persistedAutoLock(undefined)).toBe(DEFAULT_LOCK_MINUTES);
  });

  it("rejects unsupported delays", () => {
    expect(() => normalizeAutoLock(2)).toThrow();
    expect(persistedAutoLock(2)).toBe(DEFAULT_LOCK_MINUTES);
  });
});
