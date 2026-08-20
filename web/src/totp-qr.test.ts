import { describe, expect, it } from "vitest";

import { validateTotpQrPayload } from "./totp-qr";

describe("TOTP QR payload validation", () => {
  it("accepts a complete otpauth TOTP URI without rewriting it", () => {
    const payload = "otpauth://totp/Example:alice%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45";
    expect(validateTotpQrPayload(payload)).toBe(payload);
  });

  it.each([
    "https://example.test/not-a-totp",
    "otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/Example",
    "otpauth://totp/Example?secret=",
    "otpauth://totp/Example?secret=ONE&secret=TWO",
    "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP\n",
  ])("rejects unsafe or unsupported payload %s", (payload) => {
    expect(() => validateTotpQrPayload(payload)).toThrow();
  });
});
