/**
 * Canonical JSON identical to the app's `canonicalSyncJson` (kotlinx.serialization based):
 *
 * - object keys sorted by UTF-16 code units (JavaScript's default `sort()`), no whitespace;
 * - integers only, canonical spelling, within ±(2^53 − 1); fractions, exponents, `1.0`, `-0` rejected;
 * - escapes `" \\ \n \r \t \b \f` in short form, other U+0000–U+001F as lowercase `\u00xx`;
 *   `/`, DEL, U+2028 and all non-ASCII characters are written raw (UTF-8).
 *
 * [parseStrictJson] keeps the number spelling checks that `JSON.parse` would lose.
 */

import { hasLoneSurrogate } from "./bytes.ts";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export class CanonicalJsonError extends Error {}

export function canonicalJson(value: JsonValue): string {
  return write(value, 0);
}

function write(value: JsonValue, depth: number): string {
  if (depth > 256) throw new CanonicalJsonError("JSON nesting too deep");
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return writeNumber(value);
  if (typeof value === "string") return writeString(value);
  if (Array.isArray(value)) return "[" + value.map((v) => write(v, depth + 1)).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => writeString(k) + ":" + write((value as JsonObject)[k], depth + 1)).join(",") + "}";
  }
  throw new CanonicalJsonError(`Unsupported JSON value of type ${typeof value}`);
}

function writeNumber(n: number): string {
  if (!Number.isSafeInteger(n)) throw new CanonicalJsonError(`Only safe integers are canonical, got ${n}`);
  if (Object.is(n, -0)) throw new CanonicalJsonError("Negative zero is not canonical");
  return String(n);
}

export function writeString(s: string): string {
  if (hasLoneSurrogate(s)) throw new CanonicalJsonError("String contains a lone surrogate");
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const c = s.charCodeAt(i);
    switch (ch) {
      case '"': out += '\\"'; break;
      case "\\": out += "\\\\"; break;
      case "\n": out += "\\n"; break;
      case "\r": out += "\\r"; break;
      case "\t": out += "\\t"; break;
      case "\b": out += "\\b"; break;
      case "\f": out += "\\f"; break;
      default:
        out += c < 0x20 ? "\\u" + c.toString(16).padStart(4, "0") : ch;
    }
  }
  return out + '"';
}

/** Strict RFC 8259 parser: integer-only numbers, no duplicate keys, no trailing data. */
export function parseStrictJson(text: string): JsonValue {
  const p = new Parser(text);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (p.i !== text.length) p.fail("trailing data");
  return v;
}

class Parser {
  i = 0;
  constructor(private readonly s: string) {}

  fail(msg: string): never {
    throw new CanonicalJsonError(`Invalid JSON at offset ${this.i}: ${msg}`);
  }

  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else break;
    }
  }

  value(depth: number): JsonValue {
    if (depth > 256) this.fail("nesting too deep");
    const c = this.s[this.i];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    if (this.s.startsWith("true", this.i)) { this.i += 4; return true; }
    if (this.s.startsWith("false", this.i)) { this.i += 5; return false; }
    if (this.s.startsWith("null", this.i)) { this.i += 4; return null; }
    return this.fail("unexpected character");
  }

  object(depth: number): JsonObject {
    this.i++;
    const out: JsonObject = {};
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.i] === "}") { this.i++; return out; }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail("expected key");
      const key = this.string();
      if (seen.has(key)) this.fail(`duplicate key ${JSON.stringify(key)}`);
      seen.add(key);
      this.ws();
      if (this.s[this.i] !== ":") this.fail("expected ':'");
      this.i++;
      this.ws();
      const v = this.value(depth + 1);
      // defineProperty keeps "__proto__" an ordinary own key.
      Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
      this.ws();
      const c = this.s[this.i++];
      if (c === "}") return out;
      if (c !== ",") this.fail("expected ',' or '}'");
    }
  }

  array(depth: number): JsonValue[] {
    this.i++;
    const out: JsonValue[] = [];
    this.ws();
    if (this.s[this.i] === "]") { this.i++; return out; }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === "]") return out;
      if (c !== ",") this.fail("expected ',' or ']'");
    }
  }

  string(): string {
    this.i++;
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) this.fail("unterminated string");
      const c = this.s[this.i++];
      if (c === '"') return out;
      if (c === "\\") {
        const e = this.s[this.i++];
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default: this.fail("bad escape");
        }
      } else {
        if (c.charCodeAt(0) < 0x20) this.fail("raw control character in string");
        out += c;
      }
    }
  }

  number(): number {
    const m = /^-?(0|[1-9][0-9]*)/.exec(this.s.slice(this.i));
    if (!m) this.fail("bad number");
    const text = m[0];
    const next = this.s[this.i + text.length];
    if (next === "." || next === "e" || next === "E") this.fail("only integers are allowed");
    if (text === "-0") this.fail("negative zero is not allowed");
    const n = Number(text);
    if (!Number.isSafeInteger(n)) this.fail("integer outside ±9007199254740991");
    this.i += text.length;
    return n;
  }
}
