import jsQR from "jsqr";

const MAX_QR_FILE_BYTES = 8 * 1024 * 1024;
const MAX_QR_SIDE = 4096;
const MAX_DECODE_SIDE = 2048;
const MAX_PAYLOAD_LENGTH = 8192;

/** Decodes one local image without uploading it or retaining its pixels. */
export async function decodeTotpQrFile(file: File): Promise<string> {
  if (file.size === 0 || file.size > MAX_QR_FILE_BYTES || !file.type.startsWith("image/")) {
    throw new Error("Choose a PNG, JPEG, or WebP QR image smaller than 8 MiB.");
  }

  const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  try {
    if (
      bitmap.width === 0
      || bitmap.height === 0
      || bitmap.width > MAX_QR_SIDE
      || bitmap.height > MAX_QR_SIDE
    ) {
      throw new Error("The QR image dimensions are outside the safe limit.");
    }
    const scale = Math.min(1, MAX_DECODE_SIDE / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (context === null) throw new Error("This browser cannot read QR image pixels.");
    context.imageSmoothingEnabled = false;
    context.drawImage(bitmap, 0, 0, width, height);
    const pixels = context.getImageData(0, 0, width, height);
    const decoded = jsQR(pixels.data, width, height, { inversionAttempts: "attemptBoth" });
    pixels.data.fill(0);
    canvas.width = 1;
    canvas.height = 1;
    if (decoded === null) throw new Error("No readable QR code was found in that image.");
    return validateTotpQrPayload(decoded.data);
  } finally {
    bitmap.close();
  }
}

/** Rejects non-TOTP QR payloads before they enter the vault editor. */
export function validateTotpQrPayload(payload: string): string {
  if (
    payload.length === 0
    || payload.length > MAX_PAYLOAD_LENGTH
    || [...payload].some((character) => character < " " || character === "\u007f")
  ) {
    throw new Error("The QR code payload is malformed.");
  }
  let url: URL;
  try {
    url = new URL(payload);
  } catch {
    throw new Error("The QR code does not contain an otpauth URI.");
  }
  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw new Error("Only otpauth TOTP QR codes can be added to a login.");
  }
  const secrets = url.searchParams.getAll("secret");
  if (secrets.length !== 1 || secrets[0]?.trim() === "") {
    throw new Error("The TOTP QR code has no usable secret.");
  }
  return payload;
}
