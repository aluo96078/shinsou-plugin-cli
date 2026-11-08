/** `shinsou-plugin`: the Shinsou X plugin author CLI. */

import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import qrcode from "qrcode-terminal";
import { buildProject } from "./core/build.ts";
import { createKeyFile, describeKey, keyPath, readKeyFile, saveKeyFile, unlockKeyFile, type LoadedKey } from "./core/keystore.ts";
import { lintBuild } from "./core/lint.ts";
import { refreshRevocations, revokeKey, rotateKey, signExistingRepository, signRepository, type SignedOutput } from "./core/publish.ts";
import { loadState } from "./core/state.ts";
import { initProject, TEMPLATES, templatesDir, type TemplateName } from "./commands/init.ts";
import { serveProject } from "./commands/serve.ts";
import { runTests } from "./runner/harness.ts";
import { cpSync, mkdirSync } from "node:fs";
import { join } from "node:path";

declare const __CLI_VERSION__: string;
const VERSION = typeof __CLI_VERSION__ === "string" ? __CLI_VERSION__ : "0.0.0-dev";

const HELP = `shinsou-plugin ${VERSION} — Shinsou X 套件作者工具

用法：shinsou-plugin <指令> [選項]

  keygen [--name <名稱>] [--passphrase]     產生 Ed25519 發佈者金鑰
  fingerprint [--key <名稱>]                顯示金鑰指紋
  init [目錄] [--template manga|novel|mixed|async] [--id <packageId>] [--name <名稱>] [--lang <語言>]
  build                                     打包腳本並產生 index.json 與 sidecar
  lint                                      權限、origin、名稱與大小檢查
  test [--record] [--update] [--only <名稱>] 以錄製的 HTTP fixture 執行 hook
  serve [--host 127.0.0.1|lan|<區網 IP>] [--port <埠>]   開發者用未簽章儲存庫（即時重建）
  sign [--key <名稱>] [--mirror <URL>]... [--out <目錄>]  簽署 repo/index/sidecar/撤回清單
  sign-repo --mirror <URL>... [--key <名稱>] [--out <目錄>] [--flat]  簽署既有的多套件儲存庫（repo.json/index.json/sidecars）
  refresh [--key <名稱>] [--mirror <URL>]... [--if-due] [--flat]  重簽撤回清單（延長 expiresAt；--if-due 只在剩不到一半效期時重簽）
  revoke <sha256>... [--key <名稱>]                       撤回已發佈的版本
  rotate --to <新金鑰> [--key <舊金鑰>]                    金鑰輪替（雙簽）並以新金鑰重簽
  revoke-key [--key <名稱>]                               金鑰自我撤銷
  ci-template                                             寫入定期 refresh 的 GitHub Actions

共同選項：--dir <專案目錄>（預設目前目錄）、--days <撤回清單有效天數，預設 30>
環境變數：SHINSOU_PLUGIN_PASSPHRASE、SHINSOU_PLUGIN_NEW_PASSPHRASE、SHINSOU_PLUGIN_KEY（CI 用金鑰 JSON）、
          SHINSOU_PLUGIN_HOME（金鑰目錄，預設 ~/.config/shinsou-plugin）`;

async function prompt(question: string, hidden: boolean): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  if (hidden) {
    const r = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
    r._writeToOutput = (s: string) => {
      if (s.includes(question)) r.output.write(s);
    };
  }
  return new Promise((done) =>
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stderr.write("\n");
      done(answer);
    }),
  );
}

async function passphraseFor(name: string, envName = "SHINSOU_PLUGIN_PASSPHRASE"): Promise<string | undefined> {
  if (process.env[envName]) return process.env[envName];
  if (!process.stdin.isTTY) return undefined;
  return prompt(`金鑰 '${name}' 的密語：`, true);
}

async function loadKey(name: string, envName?: string): Promise<LoadedKey> {
  const file = readKeyFile(name);
  return unlockKeyFile(file, file.encryption ? await passphraseFor(name, envName) : undefined);
}

function defaultKeyName(dir: string, given?: string): string {
  return given ?? loadState(dir).currentKey?.name ?? "default";
}

function printSigned(outputs: SignedOutput[]) {
  for (const o of outputs) {
    console.log(`✓ ${o.mirror}`);
    console.log(`  → ${o.dir}`);
    for (const d of o.documents) console.log(`    ${d.documentId}  sequence=${d.sequence}`);
  }
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(HELP);
    return 0;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return 0;
  }
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      dir: { type: "string" },
      name: { type: "string" },
      key: { type: "string" },
      to: { type: "string" },
      template: { type: "string" },
      id: { type: "string" },
      lang: { type: "string" },
      passphrase: { type: "boolean" },
      mirror: { type: "string", multiple: true },
      out: { type: "string" },
      days: { type: "string" },
      host: { type: "string" },
      port: { type: "string" },
      record: { type: "boolean" },
      update: { type: "boolean" },
      only: { type: "string" },
      force: { type: "boolean" },
      flat: { type: "boolean" },
      "if-due": { type: "boolean" },
    },
  });
  const dir = resolve(values.dir ?? (command === "init" ? positionals[0] ?? "." : "."));
  const ttlSeconds = values.days ? Math.round(Number(values.days) * 86400) : undefined;
  if (ttlSeconds !== undefined && (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0)) throw new Error("--days 必須是正數");

  switch (command) {
    case "keygen": {
      const name = values.name ?? "default";
      if (existsSync(keyPath(name)) && !values.force) throw new Error(`金鑰 '${name}' 已存在（${keyPath(name)}）；要覆寫請加 --force，但舊金鑰簽過的儲存庫將無法再更新`);
      let passphrase = process.env.SHINSOU_PLUGIN_PASSPHRASE;
      if (!passphrase && process.stdin.isTTY) {
        passphrase = await prompt(values.passphrase ? "設定密語：" : "設定密語（留空則不加密）：", true);
        if (passphrase) {
          const again = await prompt("再輸入一次：", true);
          if (again !== passphrase) throw new Error("兩次輸入的密語不同");
        }
      }
      if (values.passphrase && !passphrase) throw new Error("--passphrase 需要密語（互動輸入或 SHINSOU_PLUGIN_PASSPHRASE）");
      const file = createKeyFile({ name, passphrase: passphrase || undefined });
      const path = saveKeyFile(file, { overwrite: !!values.force });
      const fp = describeKey(file);
      console.log(`已產生金鑰 '${name}'${file.encryption ? "（以密語加密）" : "（未加密）"}：${path}`);
      console.log(`完整指紋：${fp.fingerprint}`);
      console.log(`顯示指紋：${fp.display}`);
      console.log("請備份這個檔案；遺失私鑰後只能請使用者手動改信任新金鑰。");
      return 0;
    }
    case "fingerprint": {
      const file = readKeyFile(defaultKeyName(dir, values.key));
      const fp = describeKey(file);
      console.log(`${file.name}\n完整指紋：${fp.fingerprint}\n顯示指紋：${fp.display}\n公鑰：${file.publicKey}`);
      return 0;
    }
    case "init": {
      const template = (values.template ?? "manga") as TemplateName;
      if (!TEMPLATES.includes(template)) throw new Error(`--template 必須是 ${TEMPLATES.join(" | ")}`);
      const files = initProject({ dir, template, packageId: values.id, name: values.name, lang: values.lang, cliVersion: VERSION });
      console.log(`已在 ${dir} 建立 ${template} 套件專案：\n  ${files.join("\n  ")}`);
      console.log("下一步：編輯 shinsou.plugin.json（套件 ID、名稱、origin、repository.mirrors），然後執行 shinsou-plugin build && shinsou-plugin test");
      return 0;
    }
    case "build": {
      const r = await buildProject(dir);
      console.log(`✓ ${r.manifest.packageId} ${r.manifest.version} (${r.manifest.versionCode})`);
      console.log(`  sha256 ${r.sha256}\n  ${r.byteSize} bytes\n  → ${r.outDir}`);
      return 0;
    }
    case "lint": {
      const r = await buildProject(dir, { write: false });
      const report = lintBuild(r);
      for (const w of report.warnings) console.log(`⚠ [${w.rule}] ${w.message}`);
      for (const e of report.errors) console.log(`✖ [${e.rule}] ${e.message}`);
      console.log(report.errors.length ? `lint 失敗：${report.errors.length} 個錯誤、${report.warnings.length} 個警告` : `lint 通過（${report.warnings.length} 個警告）`);
      return report.errors.length ? 1 : 0;
    }
    case "test": {
      const r = await buildProject(dir);
      const results = await runTests({ projectDir: dir, manifest: r.manifest, script: r.script, record: values.record, update: values.update, only: values.only });
      for (const res of results) {
        console.log(`${res.ok ? "✓" : "✖"} ${res.name}`);
        for (const p of res.problems) console.log(`    ${p}`);
        if (!res.ok) for (const l of res.logs.slice(-10)) console.log(`    log: ${l}`);
      }
      const failed = results.filter((x) => !x.ok).length;
      console.log(failed ? `${failed}/${results.length} 個測試失敗` : `${results.length} 個測試全部通過`);
      return failed ? 1 : 0;
    }
    case "serve": {
      const s = await serveProject({ projectDir: dir, host: values.host ?? "127.0.0.1", port: Number(values.port ?? 8787) });
      console.log(`\n開發者儲存庫（未簽章，只能在 App 的「套件開發者模式」載入）：${s.baseUrl}`);
      console.log(`加入連結：${s.link}\n`);
      qrcode.generate(s.link, { small: true });
      console.log("修改檔案會自動重建；按 Ctrl+C 結束。");
      await new Promise(() => {});
      return 0;
    }
    case "sign": {
      const key = await loadKey(defaultKeyName(dir, values.key));
      printSigned(await signRepository({ projectDir: dir, key, mirrors: values.mirror, outDir: values.out, ttlSeconds }));
      console.log("把每個鏡像目錄的內容原樣上傳到對應的網址即可；.shinsou/state.json 必須一起提交。");
      return 0;
    }
    case "sign-repo": {
      const key = await loadKey(defaultKeyName(dir, values.key));
      const r = await signExistingRepository({ repoDir: dir, key, mirrors: values.mirror ?? [], outDir: values.out, ttlSeconds, flat: values.flat });
      printSigned(r.outputs);
      console.log(`已簽署 ${r.packages.length} 個套件。`);
      if (r.unchecked.length) console.log(`只核對了 SHA-256（非 Shinsou 契約，App 會略過）：${r.unchecked.join("、")}`);
      console.log("把鏡像目錄的內容放到該網址的根目錄即可；.shinsou/state.json 必須一起提交（序號與撤回清單）。");
      return 0;
    }
    case "refresh": {
      const key = await loadKey(defaultKeyName(dir, values.key));
      const signed = refreshRevocations({ projectDir: dir, key, mirrors: values.mirror, outDir: values.out, ttlSeconds, flat: values.flat, onlyIfDue: values["if-due"] });
      if (!signed.length) console.log("撤回清單還在有效期的前半，不需要重簽。");
      printSigned(signed);
      return 0;
    }
    case "revoke": {
      if (!positionals.length) throw new Error("用法：shinsou-plugin revoke <sha256>...");
      const key = await loadKey(defaultKeyName(dir, values.key));
      printSigned(refreshRevocations({ projectDir: dir, key, mirrors: values.mirror, outDir: values.out, ttlSeconds, add: positionals }));
      console.log("已撤回；App 下次取得撤回清單時會停用這些版本。");
      return 0;
    }
    case "rotate": {
      if (!values.to) throw new Error("用法：shinsou-plugin rotate --to <新金鑰名稱> [--key <舊金鑰名稱>]");
      const oldKey = await loadKey(defaultKeyName(dir, values.key));
      const newKey = await loadKey(values.to, "SHINSOU_PLUGIN_NEW_PASSPHRASE");
      const r = await rotateKey({ projectDir: dir, oldKey, newKey, mirrors: values.mirror, outDir: values.out });
      console.log(`輪替聲明（effectiveSequence=${r.effectiveSequence}，舊金鑰簽 envelope、新金鑰簽 newKeySignature）：`);
      printSigned(r.rotation);
      console.log("已用新金鑰重簽：");
      printSigned(r.resigned);
      const fp = describeKey(newKey);
      console.log(`新指紋：${fp.fingerprint}（${fp.display}）。publisher-key-rotation.json 請長期保留在儲存庫中。`);
      return 0;
    }
    case "revoke-key": {
      const name = defaultKeyName(dir, values.key);
      const key = await loadKey(name);
      printSigned(revokeKey({ projectDir: dir, key, mirrors: values.mirror, outDir: values.out }));
      console.log(`金鑰 '${name}' 已自我撤銷。若是目前金鑰，使用者必須重新信任你的新金鑰。`);
      return 0;
    }
    case "ci-template": {
      const target = join(dir, ".github", "workflows");
      mkdirSync(target, { recursive: true });
      cpSync(join(templatesDir(), "common", ".github", "workflows", "shinsou-refresh.yml"), join(target, "shinsou-refresh.yml"));
      console.log(`已寫入 ${join(target, "shinsou-refresh.yml")}；請在 GitHub 設定 SHINSOU_PLUGIN_KEY（與 SHINSOU_PLUGIN_PASSPHRASE）secrets。`);
      return 0;
    }
    default:
      console.error(`未知指令：${command}\n\n${HELP}`);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`錯誤：${(err as Error).message}`);
    process.exit(1);
  },
);
