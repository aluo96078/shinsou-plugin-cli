/** Small byte helpers shared by the codec, crypto and signing code. */

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text: string): Uint8Array {
  if (hasLoneSurrogate(text)) throw new Error("String contains a lone UTF-16 surrogate");
  return encoder.encode(text);
}

/** Strict UTF-8 decode: invalid sequences throw instead of becoming U+FFFD. */
export function decodeUtf8(bytes: Uint8Array): string {
  return strictDecoder.decode(bytes);
}

export function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Unpadded base64url, the only encoding used in envelopes and fingerprints. */
export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Decodes unpadded base64url and rejects every non-canonical spelling (padding, the `+/` alphabet,
 * whitespace, non-zero trailing bits), like the app's `canonicalBase64Url`.
 */
export function base64UrlDecodeCanonical(value: string, expectedBytes?: number): Uint8Array {
  if (value.length > 128 && expectedBytes !== undefined) throw new Error("Encoded signing material is too large");
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("Non-canonical base64url");
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  if (base64UrlEncode(bytes) !== value) throw new Error("Non-canonical base64url");
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) throw new Error("Invalid signing material size");
  return bytes;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
