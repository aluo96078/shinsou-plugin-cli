// End-to-end author workflow on the bundled templates: init → build → lint → test → sign →
// revoke → refresh → rotate → revoke-key, verifying every signed file like the app would.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildProject } from "../src/core/build.ts";
import { lintBuild } from "../src/core/lint.ts";
import { initProject } from "../src/commands/init.ts";
import { runTests } from "../src/runner/harness.ts";
import { createKeyFile, unlockKeyFile } from "../src/core/keystore.ts";
import { refreshRevocations, revokeKey, rotateKey, signRepository, mirrorSlug } from "../src/core/publish.ts";
import { verifyEnvelope, TrustError, type PayloadType } from "../src/core/envelope.ts";
import { verifyRotationPayload } from "../src/core/publisher.ts";
import { loadState } from "../src/core/state.ts";
import type { JsonObject } from "../src/core/canonical-json.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "shinsou-plugin-test-"));
const key = (name: string) => unlockKeyFile(createKeyFile({ name }));

for (const template of ["manga", "novel", "async"] as const) {
  test(`template ${template}: build, lint and hook tests pass`, async () => {
    const dir = join(tmp(), `${template}-plugin`);
    initProject({ dir, template, cliVersion: "0.1.0" });
    const built = await buildProject(dir);
    assert.ok(built.script.includes("source.v2 = __shinsouExtensionV2"));
    const report = lintBuild(built);
    assert.deepEqual(report.errors, []);
    assert.deepEqual(report.warnings, []);
    const results = await runTests({ projectDir: dir, manifest: built.manifest, script: built.script });
    for (const r of results) assert.ok(r.ok, `${r.name}: ${r.problems.join("; ")}`);
    assert.ok(results.length >= 2);
  });
}

function editManifest(dir: string, edit: (m: JsonObject) => void) {
  const path = join(dir, "shinsou.plugin.json");
  const m = JSON.parse(readFileSync(path, "utf8"));
  edit(m);
  writeFileSync(path, JSON.stringify(m, null, 2));
}

test("lint rejects misleading names, undeclared permissions and non-HTTPS origins", async () => {
  const dir = join(tmp(), "bad");
  initProject({ dir, template: "manga", cliVersion: "0.1.0" });
  editManifest(dir, (m) => {
    m.name = "Shinsou 官方漫畫";
    (m.repository as JsonObject).name = "shinsou_official";
    m.runtimePermissions = ["EXECUTE_SCRIPT"];
    const s = (m.sources as JsonObject[])[0];
    s.requestOrigins = ["http://example.com", "https://example.com/path"];
    m.requestedHostPermissions = ["REPORT_USER_MESSAGE"];
  });
  const src = join(dir, "src", "index.js");
  writeFileSync(src, readFileSync(src, "utf8") + "\nfunction x(){ bridge.setCookie('a','b','example.com','/',0); bridge.bogus(); }\n");
  const report = lintBuild(await buildProject(dir, { write: false }));
  const rules = report.errors.map((e) => `${e.rule}: ${e.message}`).join("\n");
  assert.match(rules, /misleading-name: name/);
  assert.match(rules, /misleading-name: repository\.name/);
  assert.match(rules, /bridge\.httpGet\(\) requires runtime permission NETWORK/);
  assert.match(rules, /bridge\.setCookie\(\) requires runtime permission COOKIE_STORAGE/);
  assert.match(rules, /bridge\.bogus\(\) is not a bridge operation/);
  assert.match(rules, /http:\/\/example\.com must use HTTPS/);
  assert.match(rules, /must be an exact origin/);
  assert.match(rules, /REPORT_USER_MESSAGE is never granted/);
});

test("build fails when the script's own metadata disagrees with the manifest", async () => {
  const dir = join(tmp(), "drift");
  initProject({ dir, template: "novel", cliVersion: "0.1.0" });
  const src = join(dir, "src", "index.js");
  writeFileSync(
    src,
    'var __shinsouExtensionV2 = {"contractVersion":2,"contentContract":"extension-content-v2","packageId":"other.id","contentType":"novel","contentKinds":["PLAIN_TEXT"],"systemEvents":{"protocol":"dev.shinsou.system","minVersion":1,"maxVersion":1,"required":[],"optional":[]},"requestedHostPermissions":[]};\n' +
      readFileSync(src, "utf8"),
  );
  await assert.rejects(buildProject(dir), /disagrees with shinsou\.plugin\.json/);
});

test("build rejects entries without a top-level var source", async () => {
  const dir = join(tmp(), "nosource");
  initProject({ dir, template: "novel", cliVersion: "0.1.0" });
  writeFileSync(join(dir, "src", "index.js"), "globalThis.plugin = { baseUrl: 'https://example.com' };\n");
  await assert.rejects(buildProject(dir), /must declare `var source/);
});

test("test runner enforces requestOrigins like the app", async () => {
  const dir = join(tmp(), "origin");
  initProject({ dir, template: "manga", cliVersion: "0.1.0" });
  editManifest(dir, (m) => {
    (m.sources as JsonObject[])[0].requestOrigins = ["https://other.example.com"];
  });
  const built = await buildProject(dir);
  const results = await runTests({ projectDir: dir, manifest: built.manifest, script: built.script });
  assert.ok(results.some((r) => r.problems.some((p) => p.includes("is not in requestOrigins"))));
});

test("test --record fetches missing responses once and replays them", async () => {
  const dir = join(tmp(), "record");
  initProject({ dir, template: "novel", cliVersion: "0.1.0" });
  writeFileSync(join(dir, "test", "fixtures", "sample.json"), "[]");
  writeFileSync(
    join(dir, "test", "cases.json"),
    JSON.stringify([{ name: "rank", hook: "getPopularManga", args: [1], expect: { path: "mangas", minItems: 1 } }]),
  );
  const built = await buildProject(dir);
  let calls = 0;
  const fakeFetch = (async (url: string) => {
    calls++;
    assert.equal(url, "https://example.com/rank?page=1");
    return new Response('<div class="book"><a href="/b/1">錄製</a></div>', { status: 200, headers: { "content-type": "text/html" } });
  }) as unknown as typeof fetch;
  const recorded = await runTests({ projectDir: dir, manifest: built.manifest, script: built.script, record: true, fetchImpl: fakeFetch });
  assert.ok(recorded[0].ok, recorded[0].problems.join("; "));
  assert.equal(calls, 1);
  const replay = await runTests({ projectDir: dir, manifest: built.manifest, script: built.script });
  assert.ok(replay[0].ok);
  assert.ok(existsSync(join(dir, "test", "fixtures", "rank.json")));
});

function verifyDir(dir: string, mirror: string, documentId: string, payloadType: PayloadType, pinned: { publicKey: string; fingerprint: string }) {
  const envelope = JSON.parse(readFileSync(join(dir, mirrorSlug(mirror), documentId), "utf8"));
  return verifyEnvelope({ envelope, repository: mirror, payloadType, documentId, pinned });
}

test("sign / revoke / refresh / rotate / revoke-key produce envelopes the app accepts", async () => {
  const dir = join(tmp(), "publish");
  initProject({ dir, template: "manga", packageId: "zh.publishdemo", cliVersion: "0.1.0" });
  const a = key("a");
  const b = key("b");
  const mirrors = ["https://a.example.com/repo", "https://mirror.example.net"];
  const now = 1_800_000_000;
  const out = await signRepository({ projectDir: dir, key: a, mirrors, now });
  assert.equal(out.length, 2);
  const pinA = { publicKey: a.publicKey, fingerprint: a.fingerprint };
  const pub = join(dir, "public");
  for (const m of mirrors) {
    const meta = verifyDir(pub, m, "repo.json", "repository-meta", pinA);
    assert.equal(((meta.payload as JsonObject).meta as JsonObject).signingKeyFingerprint, a.fingerprint);
    const index = verifyDir(pub, m, "index.json", "repository-index", pinA).payload as JsonObject;
    const pkg = (index.packages as JsonObject[])[0];
    const sidecar = verifyDir(pub, m, "sidecars/zh.publishdemo.json", "plugin-sidecar", pinA).payload as JsonObject;
    assert.equal((sidecar.artifact as JsonObject).sha256, pkg.sha256);
    const script = readFileSync(join(pub, mirrorSlug(m), "plugins/zh.publishdemo.js"));
    assert.equal(script.length, pkg.byteSize);
    const rev = verifyDir(pub, m, "publisher-revocations.json", "publisher-revocations", pinA).payload as JsonObject;
    assert.deepEqual(rev, { publisherId: a.fingerprint, revokedArtifacts: [], expiresAt: now + 30 * 86400 });
  }
  // A mirror's envelope does not verify for the other mirror (signatures bind the URL).
  assert.throws(
    () => {
      const envelope = JSON.parse(readFileSync(join(pub, mirrorSlug(mirrors[0]), "repo.json"), "utf8"));
      verifyEnvelope({ envelope, repository: mirrors[1], payloadType: "repository-meta", documentId: "repo.json", pinned: pinA });
    },
    (e: unknown) => e instanceof TrustError && e.category === "InvalidSignature",
  );

  const yanked = "a".repeat(64);
  refreshRevocations({ projectDir: dir, key: a, mirrors, add: [yanked.toUpperCase()], now: now + 10 });
  const rev = verifyDir(pub, mirrors[0], "publisher-revocations.json", "publisher-revocations", pinA);
  assert.deepEqual((rev.payload as JsonObject).revokedArtifacts, [yanked]);
  assert.equal(rev.sequence, 2);
  refreshRevocations({ projectDir: dir, key: a, mirrors, now: now + 20 });
  assert.equal(verifyDir(pub, mirrors[1], "publisher-revocations.json", "publisher-revocations", pinA).sequence, 3);

  const rotated = await rotateKey({ projectDir: dir, oldKey: a, newKey: b, mirrors, now: now + 30 });
  assert.equal(rotated.effectiveSequence, 1);
  // The rotation envelope is signed by the OLD key; newKeySignature by the new one.
  const rotation = verifyDir(pub, mirrors[0], "publisher-key-rotation.json", "publisher-key-rotation", pinA).payload as JsonObject;
  assert.equal(rotation.publisherId, a.fingerprint);
  assert.equal(rotation.newKeyFingerprint, b.fingerprint);
  assert.ok(verifyRotationPayload(rotation, a.fingerprint));
  const pinB = { publicKey: b.publicKey, fingerprint: b.fingerprint };
  const meta = verifyDir(pub, mirrors[0], "repo.json", "repository-meta", pinB);
  assert.equal(meta.sequence, 2);
  assert.throws(() => verifyDir(pub, mirrors[0], "repo.json", "repository-meta", pinA), (e: unknown) => e instanceof TrustError && e.category === "KeySubstitution");
  // publisherId survives rotation.
  const revB = verifyDir(pub, mirrors[0], "publisher-revocations.json", "publisher-revocations", pinB).payload as JsonObject;
  assert.equal(revB.publisherId, a.fingerprint);
  await assert.rejects(signRepository({ projectDir: dir, key: a, mirrors }), /retired key/);

  revokeKey({ projectDir: dir, key: b, mirrors });
  const revoked = verifyDir(pub, mirrors[0], "publisher-key-revoked.json", "publisher-key-revoked", pinB).payload as JsonObject;
  assert.deepEqual(revoked, { publisherId: a.fingerprint, revokedKeyFingerprint: b.fingerprint });
  assert.equal(loadState(dir).keyRevoked, true);
  await assert.rejects(signRepository({ projectDir: dir, key: b, mirrors }), /revoked/);
});
