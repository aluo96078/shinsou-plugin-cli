/**
 * Publisher keys: an Ed25519 seed in `~/.config/shinsou-plugin/keys/<name>.json` (mode 0600),
 * optionally sealed with scrypt + XChaCha20-Poly1305. The private seed never leaves this file;
 * CI can supply the same JSON through `SHINSOU_PLUGIN_KEY`.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64UrlDecodeCanonical, base64UrlEncode, utf8 } from "./bytes.ts";
import { displayFingerprint, fingerprint, publicKeyFromSeed, randomSeed } from "./crypto.ts";

export const KEY_FORMAT = "shinsou-plugin-key-v1";
export const KEY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}
export const DEFAULT_SCRYPT: ScryptParams = { N: 2 ** 17, r: 8, p: 1 };

export interface KeyFile {
  format: typeof KEY_FORMAT;
  name: string;
  algorithm: "Ed25519";
  publicKey: string;
  fingerprint: string;
  createdAt: string;
  /** Plain seed (base64url) when unencrypted. */
  seed?: string;
  encryption?: {
    kdf: "scrypt";
    N: number;
    r: number;
    p: number;
    salt: string;
    cipher: "xchacha20poly1305";
    nonce: string;
    ciphertext: string;
  };
}

export interface LoadedKey {
  name: string;
  seed: Uint8Array;
  publicKey: string;
  fingerprint: string;
}

export function configHome(): string {
  return process.env.SHINSOU_PLUGIN_HOME ?? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "shinsou-plugin");
}

export function keyPath(name: string): string {
  if (!KEY_NAME.test(name)) throw new Error(`Invalid key name '${name}' (letters, digits, . _ -; up to 64)`);
  return join(configHome(), "keys", `${name}.json`);
}

function aad(fp: string): Uint8Array {
  return utf8(`${KEY_FORMAT}:${fp}`);
}

export function createKeyFile(args: { name: string; seed?: Uint8Array; passphrase?: string; scryptParams?: ScryptParams }): KeyFile {
  const seed = args.seed ?? randomSeed();
  const pk = publicKeyFromSeed(seed);
  const fp = fingerprint(pk);
  const file: KeyFile = {
    format: KEY_FORMAT,
    name: args.name,
    algorithm: "Ed25519",
    publicKey: base64UrlEncode(pk),
    fingerprint: fp,
    createdAt: new Date().toISOString(),
  };
  if (args.passphrase) {
    const params = args.scryptParams ?? DEFAULT_SCRYPT;
    const salt = randomBytes(16);
    const nonce = randomBytes(24);
    const key = scrypt(utf8(args.passphrase.normalize("NFC")), salt, { N: params.N, r: params.r, p: params.p, dkLen: 32 });
    const ciphertext = xchacha20poly1305(key, nonce, aad(fp)).encrypt(seed);
    file.encryption = {
      kdf: "scrypt",
      ...params,
      salt: base64UrlEncode(salt),
      cipher: "xchacha20poly1305",
      nonce: base64UrlEncode(nonce),
      ciphertext: base64UrlEncode(ciphertext),
    };
  } else {
    file.seed = base64UrlEncode(seed);
  }
  return file;
}

export function saveKeyFile(file: KeyFile, { overwrite = false } = {}): string {
  const path = keyPath(file.name);
  if (existsSync(path) && !overwrite) throw new Error(`Key '${file.name}' already exists at ${path}`);
  const dir = join(configHome(), "keys");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

export function readKeyFile(name: string): KeyFile {
  const envKey = process.env.SHINSOU_PLUGIN_KEY;
  if (envKey) {
    // CI: the key file's JSON in a secret. Used only for the key it names.
    const file = JSON.parse(envKey) as KeyFile;
    if (file.format !== KEY_FORMAT) throw new Error("SHINSOU_PLUGIN_KEY is not a shinsou-plugin key file");
    if (file.name === name) return file;
  }
  const path = keyPath(name);
  if (!existsSync(path)) throw new Error(`Key '${name}' not found (${path}). Run: shinsou-plugin keygen --name ${name}`);
  const file = JSON.parse(readFileSync(path, "utf8")) as KeyFile;
  if (file.format !== KEY_FORMAT) throw new Error(`${path} is not a shinsou-plugin key file`);
  return file;
}

export function unlockKeyFile(file: KeyFile, passphrase?: string): LoadedKey {
  let seed: Uint8Array;
  if (file.encryption) {
    if (!passphrase) throw new Error(`Key '${file.name}' is encrypted: a passphrase is required`);
    const e = file.encryption;
    if (e.kdf !== "scrypt" || e.cipher !== "xchacha20poly1305") throw new Error("Unsupported key encryption");
    const key = scrypt(utf8(passphrase.normalize("NFC")), base64UrlDecodeCanonical(e.salt), { N: e.N, r: e.r, p: e.p, dkLen: 32 });
    try {
      seed = xchacha20poly1305(key, base64UrlDecodeCanonical(e.nonce), aad(file.fingerprint)).decrypt(base64UrlDecodeCanonical(e.ciphertext));
    } catch {
      throw new Error(`Wrong passphrase for key '${file.name}'`);
    }
  } else if (file.seed) {
    seed = base64UrlDecodeCanonical(file.seed, 32);
  } else {
    throw new Error(`Key file '${file.name}' has no seed`);
  }
  const pk = publicKeyFromSeed(seed);
  if (fingerprint(pk) !== file.fingerprint || base64UrlEncode(pk) !== file.publicKey) {
    throw new Error(`Key file '${file.name}' is corrupt: seed does not match its public key`);
  }
  return { name: file.name, seed, publicKey: file.publicKey, fingerprint: file.fingerprint };
}

export function describeKey(file: { publicKey: string; fingerprint: string }): { fingerprint: string; display: string } {
  return { fingerprint: file.fingerprint, display: displayFingerprint(base64UrlDecodeCanonical(file.publicKey, 32)) };
}
