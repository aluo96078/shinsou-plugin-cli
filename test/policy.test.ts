import { test } from "node:test";
import assert from "node:assert/strict";
import { misleadingTerm } from "../src/core/names.ts";
import { contentHostSuffixProblem, exactHttpsOriginProblem, usedBridgeOps } from "../src/core/lint.ts";
import { createKeyFile, unlockKeyFile } from "../src/core/keystore.ts";
import { fromHex } from "../src/core/bytes.ts";
import { emptyState, nextSequence } from "../src/core/state.ts";
import { isPrivateIPv4, resolveServeHost, devRepositoryLink } from "../src/commands/serve.ts";

test("misleading names are rejected in every spelling", () => {
  const bad = [
    "Official Manga",
    "OFFICIAL",
    "shinsou_official",
    "Shinsou-Official",
    "shinsou.official",
    "shinsou official",
    "ＯＦＦＩＣＩＡＬ", // full-width
    "ｓｈｉｎｓｏｕ＿ｏｆｆｉｃｉａｌ",
    "Offi_cial",
    "o.f.f.i.c.i.a.l",
    "0fficial",
    "offic1al",
    "Ofﬁcial", // ﬁ ligature
    "Óffícíal",
    "off​icial", // zero-width space
    "官方漫畫",
    "Shinsou 官方",
    "官 方",
    "官網精選",
    "公式",
    "offical",
  ];
  for (const name of bad) assert.ok(misleadingTerm(name), `should reject ${JSON.stringify(name)}`);
  const ok = ["包子漫画", "Manga Dex Reader", "zh.baozimh", "Office Comics", "Fiction Hub", "My Shinsou Plugins", "Officer K"];
  for (const name of ok) assert.equal(misleadingTerm(name), null, `should accept ${JSON.stringify(name)}`);
});

test("origins must be exact public HTTPS origins", () => {
  assert.equal(exactHttpsOriginProblem("https://example.com"), null);
  assert.equal(exactHttpsOriginProblem("https://api.example.com:8443"), null);
  for (const bad of [
    "http://example.com",
    "https://example.com/",
    "https://example.com/path",
    "https://EXAMPLE.com",
    "https://127.0.0.1",
    "https://[::1]",
    "https://localhost",
    "https://printer.local",
    "https://intranet",
    "https://example.com:443",
    "not a url",
  ]) {
    assert.ok(exactHttpsOriginProblem(bad), bad);
  }
});

test("contentHostSuffixes need at least a registrable domain (PSL hook)", () => {
  assert.equal(contentHostSuffixProblem("cdn.example.com"), null);
  assert.equal(contentHostSuffixProblem("example.com"), null);
  for (const bad of ["com", "co.jp", "github.io", ".example.com", "*.example.com", "Example.com", "1.2.3.4"]) {
    assert.ok(contentHostSuffixProblem(bad), bad);
  }
});

test("bridge op detection", () => {
  const ops = usedBridgeOps(`
    bridge.httpGet(u); bridge . httpPost(u, b);
    bridge.system.requestLogin("x"); await bridge.net.fetch(u, {});
    bridge.getCookie("a", u);
  `);
  assert.deepEqual([...ops].sort(), ["getCookie", "httpGet", "httpPost", "net.fetch", "system.requestLogin"]);
});

test("encrypted key files round-trip and reject a wrong passphrase", () => {
  const seed = fromHex("8d94428b78de0e0d51ea8dbede253ec1df364a2ab17ec1b4a9ef84876f869463");
  const file = createKeyFile({ name: "t", seed, passphrase: "correct horse", scryptParams: { N: 1024, r: 8, p: 1 } });
  assert.equal(file.seed, undefined);
  assert.equal(file.fingerprint, "sha256:IMfQZGEIGEEuX8ahaP7p5F0zvMMijIMCYhDd4gQQaxE");
  assert.deepEqual(unlockKeyFile(file, "correct horse").seed, seed);
  assert.throws(() => unlockKeyFile(file, "wrong"), /Wrong passphrase/);
  assert.throws(() => unlockKeyFile(file), /passphrase is required/);
  // A tampered public key is detected (the fingerprint is also the AEAD associated data).
  assert.throws(() => unlockKeyFile({ ...file, fingerprint: "sha256:x1-NTwsVKq5O2YjbMDEi9RLtKCI-od4r9XRSEwLP-hw" }, "correct horse"));
  const plain = createKeyFile({ name: "p", seed });
  assert.equal(unlockKeyFile(plain).publicKey, "ZebwYyKwxzG2_QYGji37aCIxmWrxXwWOqixF5cl2iqU");
});

test("sequences: unchanged content keeps its sequence, changed content strictly increases", () => {
  const s = emptyState();
  assert.equal(nextSequence(s, "index.json", { a: 1 }), 1);
  assert.equal(nextSequence(s, "index.json", { a: 1 }), 1);
  assert.equal(nextSequence(s, "index.json", { a: 2 }), 2);
  assert.equal(nextSequence(s, "repo.json", { a: 2 }), 1);
  assert.equal(nextSequence(s, "index.json", { a: 1 }), 3);
});

test("serve only binds loopback or a local private LAN address", () => {
  assert.equal(resolveServeHost("127.0.0.1"), "127.0.0.1");
  assert.equal(resolveServeHost("localhost"), "127.0.0.1");
  assert.throws(() => resolveServeHost("0.0.0.0"));
  assert.throws(() => resolveServeHost("8.8.8.8"));
  assert.throws(() => resolveServeHost("192.168.254.254")); // private but (almost surely) not ours
  assert.ok(isPrivateIPv4("192.168.1.2") && isPrivateIPv4("10.0.0.1") && isPrivateIPv4("172.20.1.1"));
  assert.ok(!isPrivateIPv4("172.32.0.1") && !isPrivateIPv4("1.1.1.1"));
  assert.equal(devRepositoryLink("http://192.168.1.5:8787"), "shinsou://add-dev-repository?url=http%3A%2F%2F192.168.1.5%3A8787");
});
