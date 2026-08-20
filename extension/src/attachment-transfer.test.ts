import { describe, expect, it } from "vitest";

import {
  decodeBase64Url,
  encodeBase64Url,
  formatFileSize,
} from "./attachment-transfer";

describe("attachment transfer framing", () => {
  it("round-trips a full bounded frame with canonical unpadded base64url", () => {
    const frame = new Uint8Array(1024 * 1024);
    for (let index = 0; index < frame.length; index += 1) frame[index] = index % 251;

    const encoded = encodeBase64Url(frame);
    const decoded = decodeBase64Url(encoded);

    expect(encoded).not.toMatch(/[+/=]/u);
    expect(decoded.length).toBe(frame.length);
    let mismatch = -1;
    for (let index = 0; index < decoded.length; index += 1) {
      if (decoded[index] !== frame[index]) {
        mismatch = index;
        break;
      }
    }
    expect(mismatch).toBe(-1);
    decoded.fill(0);
    frame.fill(0);
  });

  it.each(["A", "AB", "not+url", "with="])("rejects malformed or non-canonical input %s", (value) => {
    expect(() => decodeBase64Url(value)).toThrow();
  });

  it("formats only public byte counts", () => {
    expect(formatFileSize(1536)).toBe("1.5 KiB");
  });
});
