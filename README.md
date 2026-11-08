# @shinsou/plugin

Shinsou X 套件作者工具（指令 `shinsou-plugin`）：產生發佈者金鑰、建立套件專案、打包、靜態檢查、
用錄製的 HTTP 回應在本機沙箱跑 hook、開發者用即時伺服器，以及簽章發佈、撤回與金鑰輪替。

Shinsou X **沒有「官方」套件**：每個套件都是第三方套件，由作者自己的 Ed25519 發佈者金鑰簽章，
在 App 的沙箱中執行。不同發佈者可以發佈相同的 `packageId`，App 會把它們當成不同的套件。

> 本工具產生的簽章格式與 App 逐位元組一致：`test/fixtures/contract-v1/` 是 App 產生的共用測試向量，
> `npm test` 會重現每一個有效 envelope、拒絕每一個無效 envelope，並逐 frame 比對 SandboxProtocol v1 的 CBOR。

## 安裝

需要 Node.js 20 以上。

```bash
npm install --save-dev @shinsou/plugin
```

或全域安裝：

```bash
npm install --global @shinsou/plugin
```

> 目前尚未發佈到 npm。從原始碼使用：

```bash
git clone <this repo> shinsou-plugin-cli
```

```bash
cd shinsou-plugin-cli && npm install && npm run build && npm link
```

## 完整流程

```text
keygen → init → build → lint → test → serve（App 開發者模式試用）→ sign → 發佈
                                                       ↘ 之後：更新版本 → sign；revoke／refresh／rotate／revoke-key
```

### 1. 產生發佈者金鑰：`keygen`

```bash
shinsou-plugin keygen --name mykey
```

- 種子（私鑰）存在 `~/.config/shinsou-plugin/keys/mykey.json`，權限 `0600`（目錄 `0700`）。
  可用 `SHINSOU_PLUGIN_HOME` 改位置。
- 互動模式會詢問密語；輸入密語後種子以 **scrypt（N=2^17, r=8, p=1）＋ XChaCha20-Poly1305** 加密，
  指紋作為 AEAD 附加資料。加 `--passphrase` 表示一定要設定密語；非互動環境可用 `SHINSOU_PLUGIN_PASSPHRASE`。
- 會印出兩種指紋：
  - **完整指紋**：`sha256:` ＋ SHA-256(公鑰) 的無 padding base64url。比對一律用這個。
  - **顯示指紋**：SHA-256(公鑰) 前 16 bytes，大寫十六進位、每 4 字元一組（例如 `20C7 D064 6108 …`）。
- 請把指紋公布在你的網站，使用者可以用 `shinsou://add-repository?url=…&fp=<完整指紋>` 連結加入並自動比對。
- **備份金鑰檔**。遺失私鑰無法自動恢復，只能發佈新金鑰並請使用者手動改信任。

`shinsou-plugin fingerprint --key mykey` 可隨時再看指紋。

### 2. 建立專案：`init`

```bash
shinsou-plugin init my-plugin --template manga   # manga | novel | mixed | async
```

| 範本 | 內容 |
|---|---|
| `manga` | 以 `bridge.httpGet` ＋ `Jsoup` 解析 HTML 的漫畫來源，回傳圖片頁 |
| `novel` | 小說來源（`PLAIN_TEXT`）：定義 `getChapterText(chapter)`，直接回傳章節文字字串（上限 4 MiB） |
| `mixed` | 一個套件兩個來源：漫畫來源（`IMAGE_SEQUENCE`，`getPageList`）＋小說來源（`PLAIN_TEXT`，`getChapterText`），以各來源自己的 `contentKinds` 區分；套件層 `contentType` 為 `both`。`init` 會把產生的 `sourceId` 填進 `var sources = [...]` 的 `id` 與測試案例 |
| `async` | JSON API 來源：`async` hook、非阻塞的 `bridge.net.fetch`、多檔 ES module（打包成單一腳本） |

產生的檔案：

```text
shinsou.plugin.json      ← 唯一的事實來源：index、sidecar、腳本內的 v2 宣告都由它產生
src/index.js             ← 進入點，必須在頂層宣告 var source = {...}（多來源用 var sources = [...]）
test/cases.json          ← hook 測試案例
test/fixtures/*.json     ← 錄製的 HTTP 回應
.github/workflows/shinsou-refresh.yml   ← 定期重簽撤回清單
```

#### `shinsou.plugin.json`

```jsonc
{
  "manifestVersion": 1,
  "packageId": "zh.example",            // 小寫 [a-z0-9._-]
  "name": "範例漫畫",
  "version": "1.0.0",
  "versionCode": 1,                      // 每次發佈都必須遞增；App 拒絕降版
  "lang": "zh",
  "nsfw": false,
  "contract": "shinsou",
  "runtime": "legacy-shinsou-adapter-v2",
  "contentType": "manga",                // manga | novel | both
  "contentKinds": ["IMAGE_SEQUENCE"],    // IMAGE_SEQUENCE | PLAIN_TEXT | EPUB_SPINE
  "capabilities": ["CATALOGUE", "LATEST", "BROWSE", "METADATA", "UNITS", "CONTENT", "SEARCH"],
  "runtimePermissions": ["EXECUTE_SCRIPT", "NETWORK"],
  "requestedHostPermissions": [],
  "systemEvents": { "required": [], "optional": [] },
  "entry": "src/index.js",
  "sources": [{
    "sourceId": "1234567890123456789",   // 十進位 64-bit 整數字串（init 會自動產生）
    "legacyLongId": null,
    "name": "範例漫畫",
    "lang": "zh",
    "baseUrl": "https://example.com",
    "requestOrigins": ["https://example.com"],    // 腳本能連線的 exact HTTPS origin
    "credentialOrigins": [],                      // Host 代管 Cookie 的 origin（必須也是 request origin）
    "contentOrigins": ["https://img.example.com"],
    "browserSessionOrigins": [],                  // 最多 4 個；需要 BROWSER_CHALLENGE
    "contentHostSuffixes": []                     // 敏感：動態 CDN 後綴（見「已知限制」）
  }],
  "repository": {
    "name": "我的套件",                  // 發佈者名稱（App 顯示為「未驗證」名稱）
    "shortName": "我的套件",
    "website": "https://github.com/you/plugins",
    "mirrors": ["https://you.github.io/plugins"]  // 每個發佈網址；每個都會各簽一份
  },
  "test": { "cases": "test/cases.json", "fixtures": "test/fixtures" }
}
```

### 3. 打包：`build`

```bash
shinsou-plugin build
```

- 用 esbuild 把進入點（可 `import` 其他檔案）打包成**單一 classic script**，目標 ES2020。
- 在檔頭寫入一行 `var __shinsouExtensionV2 = {...};`，檔尾寫入 `source.v2 = __shinsouExtensionV2`。
  若原始碼已有自己的宣告（從舊套件遷移），必須與 `shinsou.plugin.json` 完全一致，否則失敗。
- 計算 SHA-256 與 byte size，產生 `index.json` 條目與 `sidecars/<id>.json`
  （`shinsou-extension-sidecar-v2`，`contractVersion` 2）。
- 把寫出的檔案重新讀回，以社群儲存庫 `test/v2-migration-smoke.js` 的通用規則檢查
  腳本宣告／index／sidecar 三方一致（版本、內容類型、capability、事件、權限、來源與 origin 綁定、digest）；
  任何不一致都會讓 build 失敗。
- 輸出到 `build/repo/`（未簽章）：

```text
build/repo/index.json
build/repo/repo.json
build/repo/plugins/<id>.js
build/repo/sidecars/<id>.json
```

### 4. 靜態檢查：`lint`

```bash
shinsou-plugin lint
```

錯誤（exit code 1）：

- **誤導性名稱**：packageId、套件名稱、來源名稱、發佈者名稱（`repository.name`／`shortName`）不得含
  「官方」、「官網」、「公式」、`official`（含 `offical`、`oficial` 等變體）。比對不分大小寫、全形／半形、
  重音符號、零寬字元、常見的數字替代（`0fficial`、`offic1al`），並忽略 `_ - . 空白` 分隔符號，
  所以 `shinsou_official`、`Ｓｈｉｎｓｏｕ．Ｏｆｆｉｃｉａｌ`、`o.f.f.i.c.i.a.l`、`官 方` 都會被拒絕。
- **權限涵蓋 bridge op**：掃描腳本用到的 `bridge.*`，例如 `httpGet`/`net.fetch` → `NETWORK`、
  `setCookie` → `COOKIE_STORAGE`、`getCookie` → `COOKIE_READ`、`getCredential*` → `CREDENTIAL_ACCESS`、
  `browserSessionRequest` → `BROWSER_CHALLENGE`、`bridge.system.requestLogin` → `REQUEST_LOGIN_UI` ＋ 登入事件。
  不存在的 op（沙箱會回 `UNKNOWN_OPERATION`）也算錯誤。
- **origin 必須是 exact HTTPS**：沒有路徑、沒有多餘的預設埠、不是 IP、localhost、`.local` 等私有網路主機。
  `credentialOrigins` 必須也在 `requestOrigins` 內；宣告 `NETWORK` 但 `requestOrigins` 是空的也算錯
  （App 會拒絕所有請求）。
- **腳本 ≤ 2 MiB**、`sourceId` 是 64-bit 整數字串、`REPORT_USER_MESSAGE` 等 tier ceiling 權限不能申請。
- `contentHostSuffixes` 規則與 App 相同：小寫 ASCII、不含前後的點、不是 IP，且依**完整 Public Suffix List**
  必須是可註冊網域（`cdn.example.com`、`example.com`、`user.github.io` 可以；`com`、`co.jp`、`github.io` 不行）。
  可在後面加上剛好是 `:1024-65535` 的後綴（例如 `hath.network:1024-65535`）以允許非特權連接埠，其他連接埠寫法一律拒絕；
  每個來源最多 8 個。清單固定版本放在 `data/public_suffix_list.dat`（與 App 內建的同一份，來源 commit 與 SHA-256 見 `data/README.md`）。
- `getCookie`/`getCookies` 需要同時宣告 `COOKIE_STORAGE` 與 `COOKIE_READ`（App 已實作）。
- 名稱可使用明確的否認字樣（`Unofficial`、`非官方`、`非公式`）；移除這些字樣後仍含有 official／官方／公式 的名稱照樣被拒絕。
- `PLAIN_TEXT` 來源應定義 `getChapterText`；`shinsou-plugin test` 對 `getChapterText` 的測試案例會檢查回傳是非空字串（或 `{ text }`）且不超過 4 MiB，
  並可用 `expect.equals`／`expect.contains` 比對文字。

警告：宣告了卻沒用到的權限（最小權限）、宣告了 capability 卻找不到對應 hook、腳本中出現未宣告的網址等。

### 5. 本機測試：`test`

```bash
shinsou-plugin test            # 以 test/fixtures 重播
shinsou-plugin test --record   # 缺少的回應實際連線抓取並存成 fixture，再重跑
shinsou-plugin test --update   # 更新 snapshot
shinsou-plugin test --only pages
```

- Hook 在 **QuickJS WASM 沙箱**（quickjs-emscripten）中執行，並載入與 App 相同的 JavaScript bridge bootstrap
  （`Jsoup`、`SManga`、`SChapter`、`Page`、`MangasPage`、`bridge.*`），另外提供 `bridge.net.fetch` 與 async hook。
- 測試用的 bridge host 會照 App 的規則拒絕：未宣告的權限、`requestOrigins` 以外的網址、非 HTTPS；
  密碼類 API 只在 Host 啟動的登入流程可用，因此測試中一律拒絕。被拒絕或缺少 fixture 都會讓案例失敗。
- `test/cases.json`：

```json
[
  { "name": "popular", "hook": "getPopularManga", "args": [1],
    "expect": { "path": "mangas", "minItems": 2, "snapshot": true } },
  { "name": "pages", "hook": "getPageList", "args": [{ "url": "/manga/1/chapter/1" }],
    "expect": { "minItems": 2, "matches": { "0.imageUrl": "https://example.com/img/1.jpg" } } }
]
```

  `expect` 可用 `path`（點路徑）、`minItems`、`notEmpty`、`matches`（子集比對）、`snapshot`
  （存在 `test/snapshots/`）。也可設定 `sourceId`、`preferences`、`credential`（只提供帳號）。
- fixture 格式：`[{ "request": { "method": "GET", "url": "…", "body"?: "…" }, "response": { "status": 200, "headers": {…}, "body": "…" } }]`。
  錄製時不會保存 `Set-Cookie`／`Authorization`／`Cookie`。

> TODO：App 的 `sandbox-core` WASM guest 公開後，`test` 會改用它執行（`src/runner/sandbox.ts` 的引擎介面已照
> SandboxProtocol v1 設計，CBOR codec 在 `src/core/sandbox-protocol.ts`），讓測試執行與 App 完全相同的程式碼。

### 6. 在 App 上試用：`serve`

```bash
shinsou-plugin serve                       # 只在本機 127.0.0.1:8787
shinsou-plugin serve --host lan            # 自動選本機的區域網路 IPv4
shinsou-plugin serve --host 192.168.1.20 --port 9000
```

- 提供 `build/repo/` 的**未簽章**開發者儲存庫，檔案一改就自動重建（失敗時繼續提供上一個成功的版本）。
- 只接受 `127.0.0.1`、`::1` 或**這台電腦**的私有區域網路位址（10/8、172.16/12、192.168/16）；拒絕 `0.0.0.0` 與公開 IP。
- 印出 `shinsou://add-dev-repository?url=…` 連結與終端機 QR code，用手機掃描即可加入。
- App 已能處理這個連結（`shinsou://add-dev-repository?url=…`）：開啟「設定 → 套件開發者模式」且位址是允許的開發伺服器位址時才會加入；開發中的套件只在沙箱執行、標示「開發中」，不能取得額外放寬。
- `GET /__shinsou-dev/status` 回傳目前的 build revision 與 SHA-256，可用來判斷是否需要重新載入。

### 7. 簽章：`sign`

```bash
shinsou-plugin sign --key mykey
shinsou-plugin sign --key mykey --mirror https://you.github.io/plugins --mirror https://cdn.example.com/plugins
```

- 為 `repo.json`、`index.json`、每個 sidecar 與 `publisher-revocations.json` 產生 `shinsou-signed-envelope-v1`。
- **簽章綁定儲存庫網址**，所以每個鏡像各簽一份，輸出到 `public/<鏡像網址>/`，例如
  `public/you.github.io_plugins/`。腳本 `plugins/<id>.js` 原樣複製（App 用 index 的 SHA-256 驗證）。
- `repo.json` 的 `meta.signingKeyFingerprint` 自動填入簽章金鑰的指紋。
- 每份文件的 `sequence` 記在 `.shinsou/state.json`，**嚴格遞增**：內容沒變就沿用原本的 sequence（新增鏡像或重跑時
  簽出相同內容），內容一變就 +1。App 會拒絕較小的 sequence（重播）與同 sequence 不同內容。
  **`.shinsou/state.json` 必須提交到版本控制**（不含任何秘密），否則換電腦或 CI 會從 1 重新開始而被 App 拒絕。
- 撤回清單預設有效 30 天（`--days` 可改）；剩不到一半時 `sign` 會自動延長。第一次簽章時，這把金鑰成為
  發佈者 ID（`publisherId` = 第一把金鑰的指紋，之後輪替也不變）。

### 7.1 簽署既有的多套件儲存庫：`sign-repo`

手工維護、一個儲存庫放多個套件（`repo.json` + `index.json` + `sidecars/` + `plugins/`）時，不需要改成
`shinsou.plugin.json` 專案，直接在儲存庫根目錄簽署：

```bash
shinsou-plugin sign-repo --mirror https://raw.githubusercontent.com/<帳號>/<儲存庫>/refs/heads/main --key <金鑰名稱>
```

- 不會修改任何原始檔；每個套件的腳本必須符合 index 的 `sha256` 與 `byteSize`，Shinsou 契約的套件還要通過和
  `build` 相同的 index／sidecar／腳本一致性檢查，任一不符就整個拒絕簽署。
- 其他契約的項目（例如 App 會略過的 `shuyue`）只核對 SHA-256，仍隨 index 一起簽署。
- 輸出在 `signed/<鏡像>/`：簽章後的 `repo.json`、`index.json`、每個 sidecar、`publisher-revocations.json`，以及腳本副本。
  把它的內容放到該網址的根目錄即可。`.shinsou/state.json` 記錄序號與撤回清單，必須一起提交。

### 8. 發佈

把 `public/<鏡像>/` 的內容原樣放到對應網址（GitHub Pages、raw、任何靜態主機）。使用者加入 `https://…/plugins`
這個基底網址；可以發 `shinsou://add-repository?url=<基底網址>&fp=<完整指紋>` 連結讓 App 自動比對指紋。

### 9. 更新版本

修改程式碼 → 把 `versionCode`（與 `version`）遞增 → `build` → `lint` → `test` → `sign`。

### 10. 撤回、續簽、輪替、撤銷金鑰

```bash
shinsou-plugin revoke 850c81d9…f7a9             # 撤回某個已發佈版本（腳本 SHA-256），可一次多個
shinsou-plugin refresh                          # 只重簽撤回清單、延長 expiresAt（CI 用）
shinsou-plugin rotate --key oldkey --to newkey  # 金鑰輪替
shinsou-plugin revoke-key --key mykey           # 金鑰自我撤銷
```

- **revoke**：把 SHA-256 加入撤回清單並重簽；App 取得後會卸載並停用這些版本。
- **refresh**：App 在發佈者的撤回清單過期後，不再從該發佈者安裝新套件或更新（已安裝的繼續執行並顯示警示）。
  所以**必須定期 refresh**。`init` 已附上 `.github/workflows/shinsou-refresh.yml`（每週一次），也可用
  `shinsou-plugin ci-template` 寫入。在 GitHub 設定 secrets：
  - `SHINSOU_PLUGIN_KEY`：金鑰檔 `~/.config/shinsou-plugin/keys/<名稱>.json` 的完整內容
  - `SHINSOU_PLUGIN_PASSPHRASE`：密語（金鑰有加密時）

  workflow 會提交更新後的 `public/` 與 `.shinsou/state.json`。
- **rotate**：舊金鑰簽 `publisher-key-rotation.json` 的 envelope，新金鑰簽 payload 裡的 `newKeySignature`
  （`dev.shinsou.publisher.rotation.v1\0` ＋ canonical JSON 聲明），接著用新金鑰重簽全部文件。
  新金鑰的密語可用 `SHINSOU_PLUGIN_NEW_PASSPHRASE`。`publisher-key-rotation.json` 請長期保留，
  還沒更新的使用者靠它換 pin。之後舊金鑰不能再簽。
- **revoke-key**：由被撤銷的金鑰自己簽 `publisher-key-revoked.json`。撤銷目前金鑰後，這個發佈者的套件全部停用，
  使用者必須重新信任新金鑰；`sign` 也會拒絕繼續使用它。撤銷已退休的金鑰只會讓它不再能驗證任何東西。

## 開發本工具

```bash
npm install
```

```bash
npm test          # 契約向量、CBOR、政策檢查、完整作者流程（node:test + tsx）
```

```bash
npm run typecheck && npm run build   # 輸出 dist/cli.js
```

- `test/fixtures/contract-v1/` 複製自 App 的 `fixtures/plugin-contract/v1/`。兩邊不一致代表協定改變，
  不是可以隨手更新的快照。
- `src/runner/legacy-bootstrap.ts` 由 `node scripts/sync-bootstrap.mjs [shinsoux 路徑]` 從 App 的
  `IosJavaScriptBootstrap.kt` 產生，App 的 bootstrap 改變時要重跑。

| 模組 | 內容 |
|---|---|
| `src/core/canonical-json.ts` | 與 App `canonicalSyncJson` 相同的正規化 JSON（UTF-16 鍵排序、只接受整數） |
| `src/core/envelope.ts` | envelope 簽章與驗證（錯誤分類與 App 相同：`Malformed`／`KeySubstitution`／`InvalidSignature`） |
| `src/core/publisher.ts` | 輪替聲明、撤回清單、金鑰自我撤銷 |
| `src/core/sandbox-protocol.ts` | SandboxProtocol v1 嚴格 CBOR codec、CHUNK 分段與串流讀取 |
| `src/core/manifest.ts`／`build.ts`／`consistency.ts`／`lint.ts` | 單一事實來源、打包、三方一致檢查、政策檢查 |
| `src/core/keystore.ts`／`state.ts`／`publish.ts` | 金鑰、sequence 狀態、簽章流程 |
| `src/runner/*` | 沙箱引擎介面、QuickJS 實作、fixture bridge host、測試 harness |

## 已知限制

- `contentHostSuffixes` 與 `COOKIE_READ` 已由 App 支援；內建的 Public Suffix List 是固定版本，與 App 版本不同步時
  （App 更新清單後），某個後綴可能在新版變成公開後綴而被 App 拒絕安裝；更新時請同步替換 `data/public_suffix_list.dat`。
- 一個專案只產生一個套件；同一發佈者的多個套件目前要分開的儲存庫（或自行合併 index）。
- 授權條款尚未決定（`package.json` 暫為 `UNLICENSED`），發佈到 npm 前需要決定。
