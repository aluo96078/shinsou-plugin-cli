# Public Suffix List

`public_suffix_list.dat` 是 [Public Suffix List](https://publicsuffix.org/)（MPL 2.0）的副本，
與 Shinsou X App 內建、固定版本的清單完全相同（App 的 `composeApp/psl/public_suffix_list.dat`）。
`lint` 用它以和 App 相同的規則檢查 `contentHostSuffixes`（必須是可註冊網域）。

- 來源：publicsuffix/list `main` @ `94ec5df7273926560d91e77c002000ba1a53fec4`（2026-11-08 取得）
- SHA-256：`762b6cbdd2dacc597b398fcd7860e2184b684125a58aa177dbdf54916a1f3430`

更新時請與 App 同步換成同一份檔案，並執行 `npm test`（測試會比對上面的 SHA-256）。
